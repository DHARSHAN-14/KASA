"""Filesystem security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, Severity
from kasa.models.snapshot import SystemSnapshot


class FilesystemAnalyzer(Analyzer):
    """Analyze filesystem mount security properties."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze mounted filesystems."""
        findings: list[Finding] = []

        for mount in snapshot.filesystems.mounts:
            if mount.mount_point == "/tmp" and "noexec" not in mount.options:  # noqa: S108
                findings.append(
                    Finding(
                        id="KASA-FS-001",
                        title="/tmp is executable",  # noqa: S108
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
