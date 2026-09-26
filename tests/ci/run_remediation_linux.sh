#!/usr/bin/env bash
set -euo pipefail

# This script installs fixtures in /etc and /opt. NEVER run it on a workstation,
# production machine or persistent self-hosted runner.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$EUID" == 0 ]] || {
  echo 'requires a disposable GitHub-hosted Linux runner' >&2; exit 1;
}
# Hosted runners may export their own container configuration paths. They
# must not leak into the separate root/rootless lab identities via runuser.
unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_STATE_HOME
unset CONTAINERS_STORAGE_CONF CONTAINERS_CONF CONTAINER_HOST CONTAINER_CONNECTION REGISTRY_AUTH_FILE
source_tree="$(realpath "$1")"
python="$(realpath "$2")"
export PATH="$(dirname "$python"):$PATH"
suite="$3"
results="$4"
[[ "$suite" =~ ^(systemd-disk|docker|podman|kubernetes)$ ]] || exit 2
[[ "$(cat /proc/1/comm)" == systemd ]] || exit 1
test ! -e /opt/a4diag-target/current
test ! -L /opt/a4diag-target/current
test ! -e /run/netns/a4diag-remediation
mkdir -p "$results" /opt/a4diag-remediation-lab
exec > >(tee -a "$results/setup.log") 2>&1
hostnamectl set-hostname a4diag-remediation-test
# The entire VM is disposable. The fixture units need a stable namespace path;
# attaching its existing namespace avoids giving test services a different lo.
ip netns attach a4diag-remediation 1
stage="$(mktemp -d /var/lib/a4l.XXXXXXXX)"
mkdir -m 755 "$stage/s" "$stage/t"
tar -C "$source_tree" --exclude=.git --exclude=.pytest_cache --exclude=__pycache__ --exclude=.venv --exclude=.worktrees --exclude=dist --exclude='*.egg-info' -cf - . | tar -xf - -C "$stage/s"
chown -R root:root "$stage"
chmod -R go-w "$stage"
chmod 0755 "$stage"
cd "$stage/s"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$PWD:$PWD/src:$PWD/packages/a4diag-builtin-plugins/src:$PWD/packages/a4diag-target-runtime/src"

case "$suite" in
  systemd-disk)
    export A4DIAG_TEST_SYSTEMD=1 A4DIAG_TEST_DISK=1
    tests=(tests/integration/test_repair_helpers.py tests/integration/test_repair_job_systemd.py tests/integration/test_service_fault_repair.py tests/integration/test_disk_remediation.py)
    ;;
  docker|podman)
    docker pull python:3.11-slim
    docker image inspect python:3.11-slim --format '{{json .RepoDigests}}' | tee "$results/container-image.json"
    docker tag python:3.11-slim a4diag-lab-python:3.11.16
    if [[ "$suite" == docker ]]; then
      export A4DIAG_TEST_DOCKER=1
      tests=(tests/integration/test_docker_repair.py)
    else
      useradd --create-home --uid 22001 a4diag-podman-test
      loginctl enable-linger a4diag-podman-test
      systemctl start user@22001.service podman.socket
      docker save a4diag-lab-python:3.11.16 -o "$stage/python-image.tar"
      chmod 0644 "$stage/python-image.tar"
      podman load -i "$stage/python-image.tar"
      runuser --user a4diag-podman-test -- env XDG_RUNTIME_DIR=/run/user/22001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/22001/bus podman load -i "$stage/python-image.tar"
      runuser --user a4diag-podman-test -- env XDG_RUNTIME_DIR=/run/user/22001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/22001/bus systemctl --user start podman.socket
      export A4DIAG_TEST_PODMAN=1
      tests=(tests/integration/test_podman_repair.py)
    fi
    ;;
  kubernetes)
    bash tests/ci/prepare_kubernetes_lab.sh
    export A4DIAG_TEST_KUBERNETES=1
    A4DIAG_K8S_TEST_IMAGE="$(cat /run/a4diag-k8s-test-image)"
    export A4DIAG_K8S_TEST_IMAGE
    tests=(tests/integration/test_kubernetes_repair.py)
    ;;
esac
"$python" -m pytest -q -ra -p no:cacheprovider --basetemp="$stage/t" --junitxml="$results/junit.xml" "${tests[@]}" 2>&1 | tee "$results/pytest.log"
"$python" tests/ci/assert_live_results.py "$results/junit.xml"
