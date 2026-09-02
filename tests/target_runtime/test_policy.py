from __future__ import annotations

import pytest

from a4diag.domain import Operation, Risk
from a4diag_target.policy import PackageGrant, PolicyDenied, TargetPolicy


def _operation(capability: str, resource: str, action: str = "replace_managed_file") -> Operation:
    return Operation(
        capability=capability,
        action=action,
        resource=resource,
        parameters={},
        model_risk=Risk.LOW,
        verify={},
        undo=None,
    )


def _policy(**changes: object) -> TargetPolicy:
    values: dict[str, object] = {
        "target_id": "lab-node-1",
        "target_fingerprint": "sha256:" + "a" * 64,
        "controller_key_fingerprint": "sha256:" + "b" * 64,
        "managed_roots": ("/etc", "/opt/lab"),
        "allowed_units": ("lab-app.service",),
        "allowed_packages": (
            PackageGrant(name="lab-agent", versions=("1.2.3",), repositories=("lab",)),
        ),
    }
    values.update(changes)
    return TargetPolicy.model_validate(values)


@pytest.mark.parametrize(
    "path",
    (
        "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys", "/home/user/.ssh/config",
        "/etc/pam.d/login", "/etc/sudoers", "/etc/sudoers.d/admin",
        "/etc/NetworkManager/system-connections/x", "/etc/sysconfig/network-scripts/ifcfg-eth0",
        "/etc/resolv.conf", "/etc/hosts", "/etc/firewalld/zones/public.xml",
        "/etc/nftables.conf", "/usr/libexec/a4diag/a4diag-transport-helper",
        "/etc/a4diag-target/policy.json", "/var/lib/a4diag-target/replay.sqlite3",
        "/var/lib/a4diag-target/audit/log", "/etc/cron.d/job", "/var/spool/cron/root",
        "/proc/sys/net/ipv4/ip_forward", "/etc/sysctl.conf", "/etc/selinux/config",
        "/etc/libvirt/qemu/vm.xml", "/var/lib/libvirt/images/vm.qcow2", "/usr/bin/qemu-kvm",
    ),
)
def test_protected_paths_override_even_broad_managed_root(path: str) -> None:
    with pytest.raises(PolicyDenied, match="protected_resource"):
        _policy().authorize(_operation("files", path))


@pytest.mark.parametrize(
    "unit",
    ("sshd.service", "NetworkManager.service", "firewalld.service", "libvirtd.service", "cron.service", "a4diag-target-executor.service"),
)
def test_control_plane_units_cannot_be_granted(unit: str) -> None:
    with pytest.raises(ValueError):
        _policy(allowed_units=(unit,))


@pytest.mark.parametrize(
    "package",
    ("openssh-server", "sudo", "pam", "NetworkManager", "firewalld", "nftables", "libvirt", "qemu-kvm", "selinux-policy", "kernel", "a4diag-target-runtime"),
)
def test_control_plane_packages_cannot_be_granted(package: str) -> None:
    with pytest.raises(ValueError):
        _policy(allowed_packages=(PackageGrant(name=package, versions=("1",), repositories=("r",)),))


def test_only_exact_managed_resources_units_and_packages_are_allowed() -> None:
    policy = _policy()
    policy.authorize(_operation("files", "/opt/lab/app.conf"))
    policy.authorize(_operation("services", "lab-app.service", action="restart"))
    policy.authorize(
        Operation(
            capability="packages", action="install_exact", resource="lab-agent",
            parameters={"name": "lab-agent", "version": "1.2.3", "repository": "lab"},
            model_risk=Risk.LOW, verify={}, undo=None,
        )
    )
    with pytest.raises(PolicyDenied):
        policy.authorize(_operation("files", "/opt/other/app.conf"))
    with pytest.raises(ValueError):
        _policy(allowed_units=("*.service",))
