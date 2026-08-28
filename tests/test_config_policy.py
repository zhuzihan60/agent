from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from a4diag.config import Config
from a4diag.policy import (
    PolicyError,
    authorize_target,
    bounded_output,
    validate_lines,
    validate_tool_params,
    validate_unit,
)


CONFIG_TEXT = """
alertmanager_url: http://alertmanager.example:9093
prometheus_url: http://prometheus.example:9090
poll_interval_seconds: 600
max_concurrency: 2
normal_report_days: 1
abnormal_report_days: 14
audit_days: 90
ssh_private_key: /var/lib/a4diag/.ssh/id_ed25519
ssh_known_hosts: /var/lib/a4diag/.ssh/known_hosts
ssh_user: a4diag-ro
targets:
  t_01:
    ip: 10.3.12.131
    ssh_port: 22122
    allowed_units:
      - node_exporter.service
      - sshd.service
""".lstrip()


def write_config(root: Path, text: str = CONFIG_TEXT) -> Path:
    path = root / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


class ConfigPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_loads_generic_values(self) -> None:
        cfg = Config.load(write_config(self.root))
        self.assertEqual(cfg.targets["t_01"].ip, "10.3.12.131")
        self.assertEqual(cfg.targets["t_01"].ssh_port, 22122)
        self.assertEqual(cfg.targets["t_01"].allowed_units,
                         ("node_exporter.service", "sshd.service"))
        self.assertEqual(cfg.ssh_user, "a4diag-ro")
        self.assertEqual(cfg.poll_interval_seconds, 600)
        self.assertEqual(cfg.max_concurrency, 2)
        self.assertEqual(cfg.normal_report_days, 1)
        self.assertEqual(cfg.abnormal_report_days, 14)
        self.assertEqual(cfg.audit_days, 90)

    def test_loads_multiple_targets(self) -> None:
        extra = (
            "\n  t_02:\n"
            "    ip: 10.3.12.132\n"
            "    ssh_port: 22122\n"
            "    allowed_units:\n"
            "      - sshd.service\n"
        )
        cfg = Config.load(write_config(self.root, CONFIG_TEXT + extra))
        self.assertEqual(set(cfg.targets), {"t_01", "t_02"})

    def test_rejects_missing_required_key(self) -> None:
        changed = CONFIG_TEXT.replace("ssh_user: a4diag-ro\n", "")
        with self.assertRaisesRegex(ValueError, "missing configuration keys"):
            Config.load(write_config(self.root, changed))

    def test_rejects_unknown_top_level_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown configuration keys"):
            Config.load(write_config(self.root, CONFIG_TEXT + "extra: true\n"))

    def test_rejects_nonpositive_poll_interval(self) -> None:
        changed = CONFIG_TEXT.replace(
            "poll_interval_seconds: 600", "poll_interval_seconds: 0"
        )
        with self.assertRaisesRegex(ValueError, "poll_interval_seconds"):
            Config.load(write_config(self.root, changed))

    def test_rejects_blank_ssh_user(self) -> None:
        changed = CONFIG_TEXT.replace("ssh_user: a4diag-ro", "ssh_user: ''")
        with self.assertRaisesRegex(ValueError, "ssh_user"):
            Config.load(write_config(self.root, changed))

    def test_rejects_invalid_target_keys(self) -> None:
        changed = CONFIG_TEXT.replace("    ssh_port: 22122", "    ssh_port: 22122\n    extra: 1")
        with self.assertRaisesRegex(ValueError, "invalid configuration keys"):
            Config.load(write_config(self.root, changed))

    def test_rejects_duplicate_allowed_units(self) -> None:
        changed = CONFIG_TEXT.replace(
            "      - sshd.service\n",
            "      - sshd.service\n      - sshd.service\n",
        )
        with self.assertRaisesRegex(ValueError, "allowed_units must be unique"):
            Config.load(write_config(self.root, changed))

    def test_rejects_target_outside_whitelist(self) -> None:
        cfg = Config.load(write_config(self.root))
        with self.assertRaisesRegex(PolicyError, "target is not allowed"):
            authorize_target(cfg, "10.3.12.99")

    def test_rejects_target_by_ip_even_when_registered(self) -> None:
        cfg = Config.load(write_config(self.root))
        registered_ip = cfg.targets["t_01"].ip
        with self.assertRaisesRegex(PolicyError, "target is not allowed"):
            authorize_target(cfg, registered_ip)

    def test_authorizes_by_registered_name_only(self) -> None:
        cfg = Config.load(write_config(self.root))
        self.assertEqual(authorize_target(cfg, "t_01").name, "t_01")

    def test_rejects_unknown_unit(self) -> None:
        cfg = Config.load(write_config(self.root))
        target = authorize_target(cfg, "t_01")
        with self.assertRaisesRegex(PolicyError, "unit is not allowed"):
            validate_unit(target, "docker.service")

    def test_rejects_invalid_journal_line_limits(self) -> None:
        for value in (0, -1, 201, True, "10"):
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    validate_lines(value)  # type: ignore[arg-type]

    def test_rejects_extra_or_shell_like_tool_parameters(self) -> None:
        with self.assertRaisesRegex(PolicyError, "invalid parameter set"):
            validate_tool_params("cpu", {"target": "t_01", "command": "id"})
        with self.assertRaisesRegex(PolicyError, "invalid target"):
            validate_tool_params("cpu", {"target": "t_01;id"})

    def test_bounds_combined_output(self) -> None:
        stdout, stderr, truncated = bounded_output(b"a" * 200_000, b"b" * 100_000)
        self.assertTrue(truncated)
        self.assertLessEqual(len(stdout.encode()) + len(stderr.encode()), 262_144)


if __name__ == "__main__":
    unittest.main()
