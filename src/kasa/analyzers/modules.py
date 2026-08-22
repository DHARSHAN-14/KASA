"""Kernel module security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot


class ModuleAnalyzer(Analyzer):
    """Analyze kernel module exposure."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze loaded kernel modules."""
        findings: list[Finding] = []

        if snapshot.modules.loaded:
            findings.append(
                Finding(
                    id="KASA-MODULE-001",
                    title="Loadable kernel modules are active",
                    description=(
                        f"{len(snapshot.modules.loaded)} kernel modules are "
                        "currently loaded."
                    ),
                    severity=Severity.INFO,
                    category="kernel-modules",
                    evidence_keys=["module.inventory"],
                    evidence=[
                        FindingEvidence(
                            key="module.inventory",
                            value={
                                "count": len(snapshot.modules.loaded),
                                "modules": snapshot.modules.loaded,
                            },
                        )
                    ],
                    recommendation=(
                        "Review loaded modules and disable unnecessary "
                        "kernel components where appropriate."
                    ),
                )
            )

        return findings
