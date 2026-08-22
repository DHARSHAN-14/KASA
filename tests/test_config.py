"""Tests for the kernel configuration collector."""

from pathlib import Path

from kasa.collectors.config import KernelConfigCollector
from kasa.models.evidence import EvidenceStatus


def test_parse_kernel_config() -> None:
    collector = KernelConfigCollector()

    content = """
CONFIG_KASLR=y
CONFIG_BPF=m
# CONFIG_DEBUG_FS is not set
CONFIG_TEST_VALUE="example"
"""

    config = collector._parse_config(content)

    assert config["CONFIG_KASLR"] == "y"
    assert config["CONFIG_BPF"] == "m"
    assert config["CONFIG_DEBUG_FS"] == "n"
    assert config["CONFIG_TEST_VALUE"] == '"example"'


def test_missing_configuration_source_is_unavailable(
    tmp_path: Path,
) -> None:
    collector = KernelConfigCollector()

    source = tmp_path / "missing-config"

    evidence = collector._read_source(source)

    assert evidence.status is EvidenceStatus.UNAVAILABLE
    assert evidence.value is None
    assert evidence.source.path == str(source)


def test_plain_text_configuration_source(
    tmp_path: Path,
) -> None:
    collector = KernelConfigCollector()

    source = tmp_path / "config"

    source.write_text(
        "CONFIG_KASLR=y\n# CONFIG_DEBUG_FS is not set\n",
        encoding="utf-8",
    )

    evidence = collector._read_source(source)

    assert evidence.status is EvidenceStatus.AVAILABLE

    assert evidence.value["options"]["CONFIG_KASLR"] == "y"
    assert evidence.value["options"]["CONFIG_DEBUG_FS"] == "n"
    assert evidence.value["option_count"] == 2
