#!/usr/bin/env bash
set -euo pipefail

# This installer is deliberately restricted to the disposable hosted CI lab.
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'refusing k3s installation outside GitHub-hosted Actions' >&2
  exit 1
}
[[ ${EUID} -eq 0 && $(hostname) == a4diag-remediation-test ]] || {
  echo 'refusing k3s installation outside the disposable root runner' >&2
  exit 1
}
[[ $(uname -m) == x86_64 ]] || {
  echo 'pinned k3s CI asset requires x86_64' >&2
  exit 1
}
[[ -d /opt/a4diag-remediation-lab ]] || {
  echo 'disposable lab directory is missing' >&2
  exit 1
}
for path in /opt/a4diag-target/current /usr/local/bin/k3s /etc/systemd/system/a4diag-ci-k3s.service /var/lib/rancher/k3s; do
  if [[ -e ${path} || -L ${path} ]]; then
    echo "refusing to overwrite existing target or cluster state: ${path}" >&2
    exit 1
  fi
done
for service in k3s.service k3s-agent.service a4diag-ci-k3s.service; do
  if systemctl cat "${service}" >/dev/null 2>&1 || systemctl is-active --quiet "${service}"; then
    echo "refusing to replace an existing cluster service: ${service}" >&2
    exit 1
  fi
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
tmp=$(mktemp -d /opt/a4diag-remediation-lab/k3s-download.XXXXXX)
cleanup() {
  rm -f -- "${tmp}/k3s" "${tmp}/sha256sum-amd64.txt" "${tmp}/python.tar"
  rmdir -- "${tmp}"
}
trap cleanup EXIT

release='v1.35.5%2Bk3s1'
asset_base="https://github.com/k3s-io/k3s/releases/download/${release}"
curl --fail --location --silent --show-error --connect-timeout 10 --max-time 180 --retry 3 --output "${tmp}/k3s" "${asset_base}/k3s"
curl --fail --location --silent --show-error --connect-timeout 10 --max-time 60 --retry 3 --output "${tmp}/sha256sum-amd64.txt" "${asset_base}/sha256sum-amd64.txt"
expected=$(awk '$2 == "k3s" && length($1) == 64 { print $1 }' "${tmp}/sha256sum-amd64.txt")
[[ ${expected} =~ ^[[:xdigit:]]{64}$ ]] || {
  echo 'official k3s checksum entry is absent or ambiguous' >&2
  exit 1
}
actual=$(sha256sum "${tmp}/k3s" | awk '{print $1}')
[[ ${actual} == "${expected}" ]] || {
  echo 'k3s release checksum mismatch' >&2
  exit 1
}

install -m 0755 "${tmp}/k3s" /usr/local/bin/k3s
install -m 0644 "${script_dir}/lab-k3s.service" /etc/systemd/system/a4diag-ci-k3s.service
systemctl daemon-reload
systemctl enable --now a4diag-ci-k3s.service

# The API may not accept requests immediately after systemd reports startup.
ready=false
deadline=$((SECONDS + 180))
while ((SECONDS < deadline)); do
  if timeout 4 /usr/local/bin/k3s kubectl wait --request-timeout=3s --for=condition=Ready node/a4diag-remediation-test --timeout=2s >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
[[ ${ready} == true ]] || {
  systemctl status a4diag-ci-k3s.service --no-pager >&2 || true
  echo 'k3s node did not become Ready within 180 seconds' >&2
  exit 1
}

docker info >/dev/null
docker pull --platform linux/amd64 docker.io/library/python:3.11-slim
docker save --output "${tmp}/python.tar" docker.io/library/python:3.11-slim
/usr/local/bin/k3s ctr -n k8s.io images import "${tmp}/python.tar"
# `ctr images inspect` renders a tree, not JSON. Resolve the exact imported
# reference from containerd's table; the digest validation below rejects zero
# or multiple matches as well as malformed output.
digest=$(/usr/local/bin/k3s ctr -n k8s.io images list 'name==docker.io/library/python:3.11-slim' |
  awk '$1 == "docker.io/library/python:3.11-slim" { print $3 }')
[[ ${digest} =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo 'imported Python image has no immutable manifest digest' >&2
  exit 1
}
image="docker.io/library/python@${digest}"
/usr/local/bin/k3s ctr -n k8s.io images tag docker.io/library/python:3.11-slim "${image}"
/usr/local/bin/k3s crictl inspecti "${image}" >/dev/null
umask 077
printf '%s\n' "${image}" > /run/a4diag-k8s-test-image
echo "prepared disposable k3s lab with ${image}"
