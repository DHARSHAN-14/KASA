"""Tests for the kernel collector."""

from pathlib import Path

from kasa.collectors.kernel import KernelCollector


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
