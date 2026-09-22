from __future__ import annotations

import pytest
from pydantic import ValidationError

from a4diag.domain import CapabilityGrant, RepairBinding, TargetConfig, TargetMode
from a4diag.init_config import InitRequest, InitService, TargetInit
from a4diag.recovery import RecoveryCheck
from a4diag.repair_profiles import RepairProfile, profile_digest
from a4diag_target.policy import PolicyDenied, TargetPolicy


class _Transport:
    def probe(self, target: TargetInit) -> str:
        return "sha256:" + "a" * 64


class _Model:
    def probe(self, config: object) -> None:
        raise AssertionError("no model probe expected")


def _profile(**changes: object) -> RepairProfile:
    values: dict[str, object] = {
        "id": "web",
        "target_id": "demo",
        "capability": "services",
        "resource": "demo.service",
        "actions": ("restart",),
        "constraints": {
            "verification_window_seconds": 60,
            "sample_interval_seconds": 5,
        },
        "recovery_check_ids": ("health",),
        "expires_at": 2_000_000_000,
    }
    values.update(changes)
    return RepairProfile.model_validate(values)


def _check() -> RecoveryCheck:
    return RecoveryCheck(
        id="health", kind="service_active", resource="demo.service"
    )


def test_default_profile_is_not_standing_authorization() -> None:
    profile = RepairProfile(
        id="web",
        target_id="demo",
        capability="services",
        resource="demo.service",
        actions=("restart",),
        constraints={},
        recovery_check_ids=("health",),
        expires_at=2_000_000_000,
    )

    assert profile.standing_authorization is False
    assert profile.cooldown_seconds == 600
    assert profile.hourly_limit == 2
    assert len(profile_digest(profile)) == 64


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("cooldown_seconds", True),
        ("hourly_limit", False),
        ("expires_at", True),
    ),
)
def test_profile_integer_fields_do_not_accept_booleans(field: str, value: bool) -> None:
    with pytest.raises(ValidationError):
        _profile(**{field: value})


def test_services_constraints_are_closed_and_strict() -> None:
    constraints = _profile(constraints={}).constraints
    assert constraints.verification_window_seconds == 60
    assert constraints.sample_interval_seconds == 5
    with pytest.raises(ValidationError):
        _profile(constraints={"command": "sh -c id"})
    with pytest.raises(ValidationError):
        _profile(constraints={"verification_window_seconds": True})
    with pytest.raises(ValidationError):
        _profile(constraints={"sample_interval_seconds": False})


@pytest.mark.parametrize(
    "constraints",
    (
        {"verification_window_seconds": 59},
        {"verification_window_seconds": 601},
        {"sample_interval_seconds": 0},
        {"sample_interval_seconds": 6},
    ),
)
def test_services_constraints_enforce_verification_bounds(
    constraints: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _profile(constraints=constraints)


def test_constraint_keys_that_collide_after_unicode_normalization_are_rejected() -> None:
    with pytest.raises(ValidationError, match="collide"):
        _profile(constraints={"e\u0301": 1, "\u00e9": 2})


@pytest.mark.parametrize(
    "changes",
    (
        {"recovery_check_ids": ()},
        {"recovery_check_ids": ("health", "health")},
        {"actions": ()},
        {"actions": ("restart", "restart")},
        {"actions": ("stop",)},
        {"expires_at": None},
        {"capability": "packages"},
        {"resource": "demo.service;id"},
        {"actions": ("restart;id",)},
    ),
)
def test_profile_rejects_empty_duplicate_unbounded_or_unsupported_values(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _profile(**changes)


def test_profile_digest_is_canonical_and_detects_controller_target_drift() -> None:
    controller = _profile(constraints={})
    equivalent = _profile(
        constraints={
            "verification_window_seconds": 60,
            "sample_interval_seconds": 5,
        }
    )
    drifted = _profile(actions=("start",))

    assert profile_digest(controller) == profile_digest(equivalent)
    assert profile_digest(controller) != profile_digest(drifted)


def test_repair_binding_is_strict_immutable_and_prepare_may_omit_preconditions() -> None:
    binding = RepairBinding(
        profile_id="web", profile_digest="a" * 64, preconditions_digest=None
    )
    assert binding.preconditions_digest is None
    with pytest.raises(ValidationError):
        RepairBinding(
            profile_id="web",
            profile_digest="a" * 64,
            preconditions_digest=None,
            extra=True,
        )
    with pytest.raises(ValidationError):
        binding.profile_id = "other"  # type: ignore[misc]


def test_controller_target_rejects_duplicate_profiles_and_unknown_recovery_checks() -> None:
    with pytest.raises(ValidationError, match="duplicate repair profile"):
        TargetConfig(
            id="demo",
            mode=TargetMode.LOCAL,
            identity_ref="target/demo",
            recovery_checks=(_check(),),
            repair_profiles=(_profile(), _profile()),
        )
    with pytest.raises(ValidationError, match="recovery check"):
        TargetConfig(
            id="demo",
            mode=TargetMode.LOCAL,
            identity_ref="target/demo",
            recovery_checks=(),
            repair_profiles=(_profile(),),
        )


def test_controller_target_profiles_must_match_their_target() -> None:
    with pytest.raises(ValidationError, match="target"):
        TargetConfig(
            id="other",
            mode=TargetMode.LOCAL,
            identity_ref="target/other",
            recovery_checks=(_check(),),
            repair_profiles=(_profile(),),
        )


def test_init_round_trip_preserves_only_explicit_profiles() -> None:
    legacy_grant = CapabilityGrant(
        name="files", resources=("/srv/cache/**",), actions=("read",)
    )
    without_profile = InitService(transport=_Transport(), model=_Model()).validate(
        InitRequest(
            targets=(
                TargetInit(
                    id="demo",
                    mode="local",
                    capabilities=(legacy_grant.model_dump(mode="python"),),
                ),
            )
        )
    )
    assert without_profile.settings.targets[0].repair_profiles == ()

    with_profile = InitService(transport=_Transport(), model=_Model()).validate(
        InitRequest(
            targets=(
                TargetInit(
                    id="demo",
                    mode="local",
                    recovery_checks=(_check(),),
                    repair_profiles=(_profile(),),
                ),
            )
        )
    )
    assert with_profile.settings.targets[0].repair_profiles == (_profile(),)


def test_target_policy_requires_explicit_exact_registered_profiles() -> None:
    policy = TargetPolicy(
        target_id="demo",
        target_fingerprint="sha256:" + "a" * 64,
        controller_key_fingerprint="sha256:" + "b" * 64,
        allowed_units=("demo.service",),
    )
    assert policy.repair_profiles == ()

    validated = TargetPolicy.model_validate(
        {**policy.model_dump(mode="python"), "repair_profiles": (_profile(),)}
    )
    assert validated.repair_profiles == (_profile(),)

    with pytest.raises(ValidationError, match="target"):
        TargetPolicy.model_validate(
            {
                **policy.model_dump(mode="python"),
                "repair_profiles": (_profile(target_id="other"),),
            }
        )


def test_target_policy_rejects_controller_profile_digest_drift() -> None:
    target_profile = _profile()
    policy = TargetPolicy(
        target_id="demo",
        target_fingerprint="sha256:" + "a" * 64,
        controller_key_fingerprint="sha256:" + "b" * 64,
        repair_profiles=(target_profile,),
    )

    assert policy.require_repair_profile(
        "web", profile_digest(target_profile)
    ) == target_profile
    with pytest.raises(PolicyDenied, match="profile_digest_mismatch"):
        policy.require_repair_profile(
            "web", profile_digest(_profile(actions=("start",)))
        )
    with pytest.raises(PolicyDenied, match="profile_not_granted"):
        policy.require_repair_profile("other", profile_digest(target_profile))


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _profile(surprise=True)
    with pytest.raises(ValidationError):
        RepairBinding(
            profile_id="web",
            profile_digest="a" * 64,
            preconditions_digest="b" * 64,
            surprise=True,
        )
