"""KASA command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer

from kasa.analyzers.config import KernelConfigAnalyzer
from kasa.analyzers.filesystem import FilesystemAnalyzer
from kasa.analyzers.kernel import KernelAnalyzer
from kasa.analyzers.modules import ModuleAnalyzer
from kasa.analyzers.normalize import FindingNormalizer
from kasa.analyzers.risk import RiskScorer
from kasa.collectors.system import SystemCollector
from kasa.models.analysis import AnalysisResult

app = typer.Typer(
    name="kasa",
    help="AI-assisted Linux Kernel Attack Surface Analyzer.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """KASA command-line interface."""


@app.command()
def version() -> None:
    """Display the KASA version."""
    from kasa import __version__

    typer.echo(f"KASA {__version__}")


@app.command()
def collect(
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output the complete evidence snapshot as JSON.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write the complete evidence snapshot to a JSON file.",
        ),
    ] = None,
) -> None:
    """Collect Linux kernel attack-surface evidence."""
    snapshot = SystemCollector().collect()

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            snapshot.model_dump_json(indent=2),
            encoding="utf-8",
        )
        typer.echo(f"Evidence written to: {output}")
        return

    if json_output:
        typer.echo(snapshot.model_dump_json(indent=2))
        return

    typer.echo("KASA Linux Kernel Attack Surface Analyzer")
    typer.echo()
    typer.echo("Kernel")
    typer.echo(f"  Release: {snapshot.kernel.kernel.release}")
    typer.echo()
    typer.echo("Modules")
    typer.echo(f"  Loaded: {len(snapshot.modules.loaded)}")
    typer.echo(f"  Built-in: {len(snapshot.modules.builtin)}")
    typer.echo()
    typer.echo("Filesystem")
    typer.echo(f"  Mounts: {len(snapshot.filesystems.mounts)}")
    typer.echo(f"  Supported: {len(snapshot.filesystems.supported_filesystems)}")
    typer.echo()

    if snapshot.errors:
        typer.echo(f"Collection errors: {len(snapshot.errors)}")
    else:
        typer.echo("Status: Collection successful")


@app.command()
def analyze(
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output security findings and risk assessment as JSON.",
        ),
    ] = False,
) -> None:
    """Analyze collected evidence for security findings."""
    snapshot = SystemCollector().collect()

    analyzers = [
        KernelAnalyzer(),
        KernelConfigAnalyzer(),
        ModuleAnalyzer(),
        FilesystemAnalyzer(),
    ]

    findings = []

    for analyzer in analyzers:
        findings.extend(analyzer.analyze(snapshot))

    normalized_findings = FindingNormalizer().normalize(findings)

    result = AnalysisResult(findings=normalized_findings)
    risk = RiskScorer().assess(result.findings)

    if json_output:
        output = {
            "findings": [
                finding.model_dump(mode="json") for finding in result.findings
            ],
            "risk": risk.model_dump(mode="json"),
        }

        typer.echo(json.dumps(output, indent=2))
        return

    typer.echo("KASA Security Analysis")
    typer.echo()
    typer.echo(f"Risk Score: {risk.score}")
    typer.echo(f"Risk Rating: {risk.rating.value.upper()}")
    typer.echo()
    typer.echo(f"Findings: {result.total}")
    typer.echo()

    if not result.findings:
        typer.echo("No security findings detected.")
        return

    for finding in result.findings:
        typer.echo(f"[{finding.severity.value.upper()}] {finding.id}")
        typer.echo(f"  {finding.title}")
        typer.echo(f"  {finding.description}")

        if finding.recommendation:
            typer.echo(f"  Recommendation: {finding.recommendation}")

        typer.echo()
