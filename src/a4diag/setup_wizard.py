"""`a4diag setup`: single-host setup in one command.

Asks for the model provider and API key, the services to watch on this host,
installs or reconfigures the local target runtime, then registers the host as
target ``local`` through the normal transactional ``a4diag init`` path. The
result is read-only: nothing is ever changed on the host until an
administrator separately enables writes.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from a4diag import __version__
from a4diag.init_config import CapabilityInit, InitRequest, ModelInit, TargetInit
from a4diag.recovery import EvidenceSource, RecoveryCheck

LOCAL_TARGET_ID = "local"
MAX_WATCHED_SERVICES = 4  # each service uses two of the eight evidence slots
SECRET_ROOT = Path("/etc/a4diag/secrets")
MODEL_KEY_SECRET = "model-api-key"
DASHBOARD_TOKEN_SECRET = "dashboard-token"
LOCAL_TARGET_DIR = Path("/etc/a4diag/local-target")
TARGET_CACHE_ROOT = Path("/var/cache/a4diag/target-release")
DASHBOARD_ENV = Path("/etc/a4diag/dashboard.env")
RELEASE_DOWNLOAD = "https://github.com/zhuzihan60/agent/releases/download"
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,239}\.service$")
# Same prefixes the target installer refuses to grant.
PROTECTED_UNIT_PREFIXES = (
    "ssh", "sshd", "network", "networkmanager", "firewalld", "nftables",
    "libvirt", "cron", "crond", "a4diag",
)
OTHER_UNIT_SUFFIXES = (
    ".socket", ".timer", ".target", ".mount", ".automount", ".path", ".slice", ".scope",
    ".device", ".swap",
)
COMMON_SERVICES = (
    "nginx", "apache2", "httpd", "caddy", "mysql", "mariadb", "postgresql", "redis",
    "redis-server", "mongod", "docker", "containerd", "php-fpm", "tomcat", "elasticsearch",
    "rabbitmq-server", "memcached", "haproxy",
)


@dataclass(frozen=True)
class ModelPreset:
    label: str
    base_url: str | None
    api_style: str
    default_model: str | None
    needs_key: bool = True


MODEL_PRESETS: dict[str, ModelPreset] = {
    "deepseek": ModelPreset("DeepSeek", "https://api.deepseek.com/v1", "openai", "deepseek-chat"),
    "qwen": ModelPreset("通义千问（阿里云百炼）",
                        "https://dashscope.aliyuncs.com/compatible-mode/v1", "openai", "qwen-plus"),
    "openai": ModelPreset("OpenAI", "https://api.openai.com/v1", "openai", None),
    "ollama": ModelPreset("本机 Ollama", "http://127.0.0.1:11434", "ollama", None, needs_key=False),
    "custom": ModelPreset("其他 OpenAI 兼容服务", None, "openai", None),
}


class SetupError(RuntimeError):
    pass


@dataclass
class SetupAnswers:
    preset: str
    base_url: str
    api_style: str
    model: str
    api_key: str | None
    services: tuple[str, ...]
    dashboard_lan: bool = False


@dataclass
class SetupEnvironment:
    """Everything with a side effect, injectable for tests."""

    ask: Callable[[str], str] = input
    ask_secret: Callable[[str], str] = getpass.getpass
    say: Callable[[str], None] = print
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run
    http_get: Callable[[str, dict[str, str]], object] | None = None
    init: Callable[[InitRequest], object] | None = None
    secret_root: Path = SECRET_ROOT
    local_target_dir: Path = LOCAL_TARGET_DIR
    cache_root: Path = TARGET_CACHE_ROOT
    dashboard_env: Path = DASHBOARD_ENV
    release_root: Path = Path("/opt/a4diag/current")
    target_current: Path = Path("/opt/a4diag-target/current")
    service_owner: tuple[int, int] | None = None
    extra: dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


def normalize_service(name: str) -> str:
    """Return ``name.service`` or raise when the unit cannot be watched."""
    unit = name.strip()
    if unit.endswith(OTHER_UNIT_SUFFIXES):
        raise SetupError(f"只能登记 .service 服务：{name!r}")
    if unit and not unit.endswith(".service"):
        unit += ".service"
    if not _UNIT.fullmatch(unit):
        raise SetupError(f"不是有效的服务名：{name!r}")
    if unit.casefold().startswith(PROTECTED_UNIT_PREFIXES):
        raise SetupError(f"{unit} 属于受保护的系统服务（SSH、网络、定时任务或 A4Diag 自身），不能登记")
    return unit


def parse_service_list(text: str) -> tuple[str, ...]:
    units: list[str] = []
    for item in re.split(r"[,\s]+", text.strip()):
        if item:
            unit = normalize_service(item)
            if unit not in units:
                units.append(unit)
    if len(units) > MAX_WATCHED_SERVICES:
        raise SetupError(f"最多登记 {MAX_WATCHED_SERVICES} 个服务")
    return tuple(units)


def parse_unit_listing(output: str) -> tuple[list[str], list[str]]:
    """Split ``systemctl list-units`` output into (failed, other watchable) units."""
    failed: list[str] = []
    others: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].endswith(".service"):
            continue
        unit, load, active = fields[0], fields[1], fields[2]
        if load != "loaded":
            continue
        try:
            normalize_service(unit)
        except SetupError:
            continue
        if active == "failed":
            failed.append(unit)
        elif unit.removesuffix(".service") in COMMON_SERVICES:
            others.append(unit)
    return failed, others


def _evidence_id(unit: str, suffix: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_-]", "-", unit.removesuffix(".service"))[:50].strip("-") or "svc"
    return f"{stem}-{suffix}"


def build_init_request(answers: SetupAnswers, *, secret_ref: str | None) -> InitRequest:
    sources: list[EvidenceSource] = []
    checks: list[RecoveryCheck] = []
    for unit in answers.services:
        sources.append(EvidenceSource(id=_evidence_id(unit, "state"), kind="service_state",
                                      resource=unit, max_bytes=2048))
        sources.append(EvidenceSource(id=_evidence_id(unit, "logs"), kind="service_logs",
                                      resource=unit, max_bytes=12288))
        checks.append(RecoveryCheck(id=_evidence_id(unit, "active"), kind="service_active",
                                    resource=unit))
    target = TargetInit(
        id=LOCAL_TARGET_ID,
        mode="local",
        operation_signing_key_ref=f"file:targets/{LOCAL_TARGET_ID}/operation-ed25519.pem",
        capabilities=(
            (CapabilityInit(name="services", actions=("start", "restart"),
                            resources=answers.services),)
            if answers.services else ()
        ),
        evidence_sources=tuple(sources),
        recovery_checks=tuple(checks),
    )
    model = ModelInit(base_url=answers.base_url, model=answers.model,
                      api_style=answers.api_style, api_key_ref=secret_ref)
    return InitRequest(global_mode="read_only", model=model, targets=(target,))


def target_install_document(bootstrap: dict[str, object], services: Sequence[str]) -> dict[str, object]:
    document = dict(bootstrap)
    document["managed_resources"] = [{"capability": "services", "resource": unit} for unit in services]
    document["confirm_managed_resources"] = "ENABLE" if services else "DISABLED"
    return document


def list_models(preset: ModelPreset, base_url: str, api_key: str | None,
                http_get: Callable[[str, dict[str, str]], object]) -> list[str]:
    base = base_url.rstrip("/")
    if preset.api_style == "ollama":
        payload = http_get(f"{base}/api/tags", {})
        rows = payload.get("models", []) if isinstance(payload, dict) else []
        return sorted(str(row["name"]) for row in rows if isinstance(row, dict) and row.get("name"))
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    payload = http_get(f"{base}/models", headers)
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    return sorted(str(row["id"]) for row in rows if isinstance(row, dict) and row.get("id"))


def default_http_get(url: str, headers: dict[str, str]) -> object:
    import httpx

    response = httpx.get(url, headers=headers, timeout=15.0, follow_redirects=False)
    if response.status_code == 401:
        raise SetupError("API key 无效（HTTP 401）")
    response.raise_for_status()
    if len(response.content) > 1_048_576:
        raise SetupError("模型列表过大")
    return response.json()


def write_secret(path: Path, value: str, owner: tuple[int, int] | None) -> None:
    """Atomically write a 0600 secret owned by the service account."""
    data = value.strip().encode("utf-8")
    if not data or len(data) > 4096 or b"\x00" in data or b"\n" in data:
        raise SetupError("密钥内容无效")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            if owner is not None:
                os.fchown(handle.fileno(), *owner)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# interactive steps
# ---------------------------------------------------------------------------


def _choose(env: SetupEnvironment, prompt: str, options: Sequence[str], default: int = 1) -> int:
    for index, option in enumerate(options, 1):
        env.say(f"  {index}. {option}")
    while True:
        answer = env.ask(f"{prompt} [{default}]: ").strip()
        if not answer:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer)
        env.say(f"请输入 1-{len(options)} 之间的数字")


def ask_model(env: SetupEnvironment) -> tuple[str, ModelPreset, str, str | None, str]:
    env.say("\n第 1 步：选择用来分析故障的大模型")
    keys = list(MODEL_PRESETS)
    preset_key = keys[_choose(env, "选择", [MODEL_PRESETS[key].label for key in keys]) - 1]
    preset = MODEL_PRESETS[preset_key]
    base_url = preset.base_url or env.ask("服务地址（例如 https://example.com/v1）: ").strip()
    api_key = None
    if preset.needs_key:
        api_key = env.ask_secret("API key（输入时不显示）: ").strip()
        if not api_key:
            raise SetupError("需要 API key")
    http_get = env.http_get or default_http_get
    try:
        models = list_models(preset, base_url, api_key, http_get)
    except SetupError:
        raise
    except Exception as error:  # listing is a convenience; fall back to typing a name
        env.say(f"（无法读取模型列表：{type(error).__name__}，请手动输入模型名）")
        models = []
    if models:
        shown = models[:20]
        default = shown.index(preset.default_model) + 1 if preset.default_model in shown else 1
        env.say("可用模型：")
        model = shown[_choose(env, "选择模型", shown, default) - 1]
    else:
        model = env.ask(f"模型名 [{preset.default_model or ''}]: ").strip() or (preset.default_model or "")
        if not model:
            raise SetupError("需要模型名")
    return preset_key, preset, base_url, api_key, model


def ask_services(env: SetupEnvironment) -> tuple[str, ...]:
    env.say(f"\n第 2 步：选择要监控的服务（最多 {MAX_WATCHED_SERVICES} 个）")
    listing = env.run(
        ["/usr/bin/systemctl", "list-units", "--type=service", "--all", "--no-legend",
         "--plain", "--no-pager"],
        check=False, capture_output=True, text=True, timeout=30,
    )
    failed, common = parse_unit_listing(listing.stdout or "")
    suggested = (failed + [unit for unit in common if unit not in failed])[:MAX_WATCHED_SERVICES]
    if failed:
        env.say("当前处于失败状态的服务：" + ", ".join(failed))
    if common:
        env.say("检测到的常见服务：" + ", ".join(common))
    default_text = ", ".join(suggested)
    while True:
        answer = env.ask(f"要监控的服务，逗号分隔 [{default_text or '暂不登记'}]: ").strip()
        try:
            return parse_service_list(answer or default_text)
        except SetupError as error:
            env.say(str(error))


# ---------------------------------------------------------------------------
# installation steps
# ---------------------------------------------------------------------------


def ensure_local_bootstrap(env: SetupEnvironment) -> dict[str, object]:
    from a4diag.target_bootstrap import TargetBootstrapRequest, build_target_bootstrap

    document_path = env.local_target_dir / "target-install.json"
    key_dir = env.secret_root / "targets" / LOCAL_TARGET_ID
    if not document_path.is_file():
        if key_dir.exists():
            raise SetupError(f"{key_dir} 已存在但缺少 {document_path}；请检查后删除其中一个再重试")
        staging = env.local_target_dir.parent / f".{env.local_target_dir.name}.{secrets.token_hex(4)}"
        build_target_bootstrap(
            TargetBootstrapRequest(target_id=LOCAL_TARGET_ID, allowed_source_cidrs=("127.0.0.1/32",)),
            staging, secret_root=env.secret_root / "targets", secret_owner=env.service_owner,
        )
        os.replace(staging, env.local_target_dir)
    return json.loads(document_path.read_text(encoding="utf-8"))


def install_local_target(env: SetupEnvironment, document: dict[str, object], *,
                         target_release: Path | None) -> None:
    config = env.local_target_dir / "target-install.json"
    descriptor = os.open(config.with_suffix(".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
    os.replace(config.with_suffix(".tmp"), config)
    environment = dict(os.environ)
    if target_release is not None:
        command = ["bash", str(target_release / "tools" / "install_target_lib.sh"), "install",
                   str(target_release), str(config)]
    else:
        archive = fetch_target_release(env)
        environment.update({
            "A4DIAG_TARGET_RELEASE_URL": f"file://{archive}",
            "A4DIAG_TARGET_RELEASE_SIGNATURE_URL": f"file://{archive}.sig",
            "A4DIAG_TARGET_INSTALL_CONFIG": str(config),
        })
        command = ["bash", str(env.release_root / "install-a4diag-target.sh")]
    runtime_python = env.release_root / "runtime" / "python" / "bin" / "python3.11"
    if runtime_python.is_file():
        environment.setdefault("A4DIAG_PYTHON", str(runtime_python))
    env.say("正在安装/更新本机被控端组件…")
    completed = env.run(command, check=False, env=environment, capture_output=True, text=True,
                        timeout=900)
    if completed.returncode != 0:
        tail = "\n".join((completed.stderr or completed.stdout or "").splitlines()[-15:])
        raise SetupError(f"被控端安装失败：\n{tail}")


def fetch_target_release(env: SetupEnvironment) -> Path:
    """Download (once) the signed target archive matching this controller version."""
    directory = env.cache_root / __version__
    archive = directory / "a4diag-target.tar.gz"
    if archive.is_file() and (directory / "a4diag-target.tar.gz.sig").is_file():
        return archive
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("a4diag-target.tar.gz", "a4diag-target.tar.gz.sig"):
        url = f"{RELEASE_DOWNLOAD}/v{__version__}/{name}"
        env.say(f"下载 {url}")
        completed = env.run(
            ["curl", "-fsSL", "--proto", "=https", "--tlsv1.2", "--max-time", "600",
             "-o", str(directory / f".{name}.part"), url],
            check=False, capture_output=True, text=True, timeout=660,
        )
        if completed.returncode != 0:
            raise SetupError(f"下载失败：{url}\n{completed.stderr.strip()}\n"
                             "离线环境可用 --target-release 指定已解压的被控端安装包目录")
        os.replace(directory / f".{name}.part", directory / name)
    return archive


def configure_dashboard(env: SetupEnvironment, *, lan: bool) -> str | None:
    """Return a freshly created token when the dashboard now listens beyond loopback."""
    token = None
    if lan:
        token_path = env.secret_root / DASHBOARD_TOKEN_SECRET
        token = secrets.token_urlsafe(24)
        write_secret(token_path, token, env.service_owner)
        env.dashboard_env.write_text("A4DIAG_DASHBOARD_LISTEN=0.0.0.0\n", encoding="utf-8")
    elif env.dashboard_env.exists():
        env.dashboard_env.unlink()
    env.run(["/usr/bin/systemctl", "enable", "a4diag-dashboard.service"], check=False,
            capture_output=True, timeout=30)
    env.run(["/usr/bin/systemctl", "restart", "a4diag-dashboard.service"], check=False,
            capture_output=True, timeout=30)
    return token


def run_setup(env: SetupEnvironment, *, target_release: Path | None = None,
              dashboard_lan: bool = False) -> int:
    env.say(f"A4Diag {__version__} 单机设置：这台机器既是控制端，也是被控端。")
    env.say("设置完成后默认只读：只诊断、给建议，不会修改任何东西。")
    _preset_key, preset, base_url, api_key, model = ask_model(env)
    services = ask_services(env)
    answers = SetupAnswers(preset=_preset_key, base_url=base_url, api_style=preset.api_style,
                           model=model, api_key=api_key, services=services,
                           dashboard_lan=dashboard_lan)

    env.say("\n第 3 步：安装并登记本机")
    secret_ref = None
    if answers.api_key:
        write_secret(env.secret_root / MODEL_KEY_SECRET, answers.api_key, env.service_owner)
        secret_ref = f"file:{MODEL_KEY_SECRET}"
    bootstrap = ensure_local_bootstrap(env)
    install_local_target(env, target_install_document(bootstrap, services),
                         target_release=target_release)
    request = build_init_request(answers, secret_ref=secret_ref)
    if env.init is None:
        raise SetupError("init service unavailable")
    env.init(request)
    token = configure_dashboard(env, lan=dashboard_lan)

    env.say("\n完成！")
    env.say("  诊断：sudo a4diag diagnose \"网站打不开\"")
    if token:
        env.say(f"  状态网页：http://<本机IP>:8765/?token={token}")
        env.say("  （令牌只显示这一次，已保存在 /etc/a4diag/secrets/dashboard-token）")
    else:
        env.say("  状态网页：http://127.0.0.1:8765")
        env.say("  · 在 WSL 中运行时，Windows 浏览器可直接打开 http://localhost:8765")
        env.say("  · 远程服务器：ssh -L 8765:127.0.0.1:8765 <服务器>，再打开 http://localhost:8765")
    env.say("  重新运行 sudo a4diag setup 可以更换模型或监控的服务。")
    return 0


__all__ = [
    "MODEL_PRESETS", "SetupAnswers", "SetupEnvironment", "SetupError",
    "build_init_request", "list_models", "normalize_service", "parse_service_list",
    "parse_unit_listing", "run_setup", "target_install_document", "write_secret",
]
