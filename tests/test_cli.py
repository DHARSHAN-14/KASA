"""Tests for the KASA command-line interface."""

import json

from typer.testing import CliRunner

from kasa.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "KASA 0.1.0" in result.stdout


def test_collect() -> None:
    result = runner.invoke(app, ["collect"])

    assert result.exit_code == 0
    assert "KASA Linux Kernel Attack Surface Analyzer" in result.stdout
    assert "Kernel" in result.stdout
    assert "Modules" in result.stdout
    assert "Filesystem" in result.stdout


def test_collect_json() -> None:
    result = runner.invoke(app, ["collect", "--json"])

    assert result.exit_code == 0

    data = json.loads(result.stdout)

    assert "kernel" in data
    assert "kernel_config" in data
    assert "modules" in data
    assert "filesystems" in data
    assert "errors" in data


def test_collect_json_contains_module_inventory() -> None:
    result = runner.invoke(app, ["collect", "--json"])

    assert result.exit_code == 0

    data = json.loads(result.stdout)

    assert isinstance(data["modules"]["loaded"], list)
    assert isinstance(data["modules"]["builtin"], list)


def test_analyze() -> None:
    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert "KASA Security Analysis" in result.stdout


def test_analyze_contains_finding_structure() -> None:
    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0

    if "Findings:" in result.stdout:
        assert "[" in result.stdout


def test_analyze_json() -> None:
    result = runner.invoke(app, ["analyze", "--json"])

    assert result.exit_code == 0

    data = json.loads(result.stdout)

    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_analyze_json_contains_finding_fields() -> None:
    result = runner.invoke(app, ["analyze", "--json"])

    assert result.exit_code == 0

    data = json.loads(result.stdout)

    assert data["findings"]

    finding = data["findings"][0]

    assert "id" in finding
    assert "title" in finding
    assert "description" in finding
    assert "severity" in finding
    assert "category" in finding
