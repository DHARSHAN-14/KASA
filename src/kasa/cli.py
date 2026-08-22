"""KASA command-line interface."""

import typer

app = typer.Typer(
    name="kasa",
    help="AI-assisted Linux Kernel Attack Surface Analyzer.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Display the KASA version."""
    from kasa import __version__

    typer.echo(f"KASA {__version__}")
