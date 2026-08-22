"""Kernel security analyzers."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, Severity
from kasa.models.snapshot import SystemSnapshot


class KernelAnalyzer(Analyzer):
    """Analyze kernel-level security posture."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze kernel command-line security controls."""
        findings: list[Finding] = []

        command_line = snapshot.kernel.command_line or ""

        if "lockdown=integrity" not in command_line and (
            "lockdown=confidentiality" not in command_line
        ):
            findings.append(
                Finding(
                    id="KASA-KERNEL-001",
                    title="Kernel lockdown is not enabled via command line",
                    description=(
                        "The running kernel command line does not contain an "
                        "explicit lockdown=integrity or lockdown=confidentiality "
                        "parameter."
                    ),
                    severity=Severity.LOW,
                    category="kernel-hardening",
                    evidence_keys=["kernel.command_line"],
                    recommendation=(
                        "Evaluate whether kernel lockdown should be enabled "
                        "for this system."
                    ),
                )
            )

        return findings
