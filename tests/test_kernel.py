"""Tests for the kernel collector and analyzer."""

from pathlib import Path

from kasa.analyzers.kernel import KernelAnalyzer
from kasa.collectors.filesystem import FilesystemInventory
from kasa.collectors.kernel import KernelCollector
from kasa.collectors.modules import ModuleInventory
from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    KernelInfo,
    KernelSnapshot,
)
from kasa.models.snapshot import SystemSnapshot


def test_kernel_collector_returns_kernel_information() -> None:
    snapshot = KernelCollector().collect()

    assert snapshot.kernel.release
    assert snapshot.kernel.version
    assert snapshot.kernel.machine
    assert snapshot.kernel.system


def test_kernel_collector_contains_command_line_evidence() -> None:
    snapshot = KernelCollector().collect()

    assert snapshot.evidence

    command_line = next(
        item for item in snapshot.evidence if item.key == "kernel.command_line"
    )

    assert command_line.source.path == str(Path("/proc/cmdline"))


def test_kernel_collector_contains_lockdown_evidence() -> None:
    snapshot = KernelCollector().collect()

    lockdown = next(item for item in snapshot.evidence if item.key == "kernel.lockdown")

    assert lockdown.source.path == str(Path("/sys/kernel/security/lockdown"))
    assert lockdown.status.value in {"available", "unavailable", "error"}


def test_parse_lockdown_state_integrity() -> None:
    assert (
        KernelCollector._parse_lockdown_state("none [integrity] confidentiality")
        == "integrity"
    )


def test_parse_lockdown_state_confidentiality() -> None:
    assert (
        KernelCollector._parse_lockdown_state("none integrity [confidentiality]")
        == "confidentiality"
    )


def test_parse_lockdown_state_none() -> None:
    assert (
        KernelCollector._parse_lockdown_state("[none] integrity confidentiality")
        == "none"
    )


def make_kernel_snapshot(active_mode: str) -> SystemSnapshot:
    """Create a minimal snapshot containing lockdown evidence."""
    return SystemSnapshot(
        kernel=KernelSnapshot(
            kernel=KernelInfo(
                release="test",
                version="test",
                machine="x86_64",
                node="test",
                system="Linux",
                processor="test",
            ),
            command_line="BOOT_IMAGE=test",
            lockdown=active_mode,
            evidence=[
                EvidenceItem(
                    key="kernel.lockdown",
                    value={
                        "raw": f"none [{active_mode}] confidentiality",
                        "active_mode": active_mode,
                    },
                    status=EvidenceStatus.AVAILABLE,
                    source=EvidenceSource(
                        path="/sys/kernel/security/lockdown",
                        description="Current kernel lockdown state.",
                    ),
                )
            ],
        ),
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )


def test_kernel_analyzer_reports_disabled_lockdown() -> None:
    snapshot = make_kernel_snapshot("none")

    findings = KernelAnalyzer().analyze(snapshot)

    assert len(findings) == 1
    assert findings[0].id == "KASA-KERNEL-001"
    assert findings[0].severity.value == "low"


def test_kernel_analyzer_does_not_report_integrity_lockdown() -> None:
    snapshot = make_kernel_snapshot("integrity")

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_analyzer_does_not_report_confidentiality_lockdown() -> None:
    snapshot = make_kernel_snapshot("confidentiality")

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []
