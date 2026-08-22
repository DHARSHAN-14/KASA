"""Linux kernel information collector."""

from __future__ import annotations

import platform
from pathlib import Path

from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    KernelInfo,
    KernelSnapshot,
)


class KernelCollector:
    """Collect read-only information about the running Linux kernel."""

    _PROC_CMDLINE = Path("/proc/cmdline")

    def collect(self) -> KernelSnapshot:
        """Collect kernel metadata and kernel command-line evidence."""
        errors: list[str] = []

        kernel_info = KernelInfo(
            release=platform.release(),
            version=platform.version(),
            machine=platform.machine(),
            node=platform.node(),
            system=platform.system(),
            processor=platform.processor(),
        )

        command_line, command_line_evidence, command_line_error = (
            self._collect_command_line()
        )

        if command_line_error is not None:
            errors.append(command_line_error)

        return KernelSnapshot(
            kernel=kernel_info,
            command_line=command_line,
            evidence=[command_line_evidence],
            collection_errors=errors,
        )

    def _collect_command_line(
        self,
    ) -> tuple[str | None, EvidenceItem, str | None]:
        source = EvidenceSource(
            path=str(self._PROC_CMDLINE),
            description="Kernel command-line parameters.",
        )

        try:
            raw_value = self._PROC_CMDLINE.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()

        except FileNotFoundError:
            error = f"Kernel command line not available: {self._PROC_CMDLINE}"

            return (
                None,
                EvidenceItem(
                    key="kernel.command_line",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        except OSError as exc:
            error = f"Unable to read kernel command line {self._PROC_CMDLINE}: {exc}"

            return (
                None,
                EvidenceItem(
                    key="kernel.command_line",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        return (
            raw_value,
            EvidenceItem(
                key="kernel.command_line",
                value=raw_value,
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )
