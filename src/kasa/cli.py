"""KASA command-line interface."""

import typer

from kasa.collectors.system import SystemCollector

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
def collect() -> None:
    """Collect Linux kernel attack-surface evidence."""
    snapshot = SystemCollector().collect()

    typer.echo(f"Kernel: {snapshot.kernel.kernel.release}")
    typer.echo(f"Modules loaded: {len(snapshot.modules.loaded)}")
    typer.echo(f"Modules built-in: {len(snapshot.modules.builtin)}")
    typer.echo(f"Filesystem mounts: {len(snapshot.filesystems.mounts)}")
    typer.echo(
        f"Supported filesystems: {len(snapshot.filesystems.supported_filesystems)}"
    )

    if snapshot.errors:
        typer.echo(f"Collection errors: {len(snapshot.errors)}")
