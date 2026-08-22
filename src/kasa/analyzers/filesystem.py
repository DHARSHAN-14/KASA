"""Filesystem security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, Severity
from kasa.models.snapshot import SystemSnapshot

TMP_MOUNT_POINT = "/tmp"  # noqa: S108


class FilesystemAnalyzer(Analyzer):
    """Analyze filesystem mount security properties."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze mounted filesystems."""
        findings: list[Finding] = []

        for mount in snapshot.filesystems.mounts:
            if mount.mount_point == TMP_MOUNT_POINT and "noexec" not in mount.options:
                findings.append(
                    Finding(
                        id="KASA-FS-001",
                        title="Temporary directory is executable",
                        description=(
                            "The /tmp filesystem is mounted without the noexec option."
                        ),
                        severity=Severity.LOW,
                        category="filesystem-hardening",
                        evidence_keys=["filesystem.mounts"],
                        recommendation=(
                            "Consider mounting /tmp with noexec where "
                            "compatible with system requirements."
                        ),
                    )
                )

        return findings
