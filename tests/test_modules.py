"""Tests for the kernel module collector."""

from pathlib import Path

import pytest

from kasa.collectors.modules import ModuleCollector, ModuleState


def test_parse_proc_modules_line() -> None:
    collector = ModuleCollector()

    module = collector._parse_proc_modules_line(
        "test_module 16384 2 dependency_a,dependency_b 16384 0"
    )

    assert module.name == "test_module"
    assert module.state is ModuleState.LOADED
    assert module.size == 16384
    assert module.reference_count == 2
    assert module.dependencies == [
        "dependency_a",
        "dependency_b",
    ]
    assert module.source == "/proc/modules"


def test_parse_proc_modules_without_dependencies() -> None:
    collector = ModuleCollector()

    module = collector._parse_proc_modules_line("test_module 8192 0 - 16384 0")

    assert module.dependencies == []


def test_invalid_proc_modules_line() -> None:
    collector = ModuleCollector()

    with pytest.raises(ValueError, match="expected at least 6 fields"):
        collector._parse_proc_modules_line("invalid")


def test_invalid_module_size() -> None:
    collector = ModuleCollector()

    with pytest.raises(ValueError, match="invalid module size"):
        collector._parse_proc_modules_line("test_module invalid 2 - 16384 0")


def test_invalid_reference_count() -> None:
    collector = ModuleCollector()

    with pytest.raises(ValueError, match="invalid reference count"):
        collector._parse_proc_modules_line("test_module 16384 invalid - 16384 0")


def test_missing_loaded_module_interface(
    tmp_path: Path,
) -> None:
    collector = ModuleCollector()
    collector._PROC_MODULES = tmp_path / "missing"

    modules, error = collector._collect_loaded_modules()

    assert modules == []
    assert error is not None
    assert "Module interface unavailable" in error


def test_loaded_modules_are_collected(
    tmp_path: Path,
) -> None:
    collector = ModuleCollector()

    proc_modules = tmp_path / "modules"

    proc_modules.write_text(
        "test_module 16384 2 dependency_a,dependency_b 16384 0\n"
        "another_module 8192 0 - 16384 0\n",
        encoding="utf-8",
    )

    collector._PROC_MODULES = proc_modules

    modules, error = collector._collect_loaded_modules()

    assert error is None
    assert len(modules) == 2

    assert modules[0].name == "test_module"
    assert modules[0].state is ModuleState.LOADED
    assert modules[0].size == 16384
    assert modules[0].reference_count == 2

    assert modules[1].name == "another_module"
    assert modules[1].dependencies == []


def test_builtin_modules_missing() -> None:
    collector = ModuleCollector()

    builtin, source, error = collector._collect_builtin_modules(
        "definitely-nonexistent-kernel-release"
    )

    assert builtin == []
    assert source is None
    assert error is not None
    assert "Built-in module metadata unavailable" in error


def test_module_inventory_model() -> None:
    collector = ModuleCollector()

    inventory = collector.collect("definitely-nonexistent-kernel-release")

    assert inventory.loaded
    assert inventory.sources
    assert inventory.errors


def test_module_inventory_contains_loaded_module() -> None:
    collector = ModuleCollector()

    inventory = collector.collect("definitely-nonexistent-kernel-release")

    assert inventory.loaded[0].state is ModuleState.LOADED
    assert inventory.loaded[0].name
