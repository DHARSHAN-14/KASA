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
    _LOCKDOWN = Path("/sys/kernel/security/lockdown")

    def collect(self) -> KernelSnapshot:
        """Collect kernel metadata and kernel security evidence."""
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

        lockdown, lockdown_evidence, lockdown_error = self._collect_lockdown()

        if lockdown_error is not None:
            errors.append(lockdown_error)

        return KernelSnapshot(
            kernel=kernel_info,
            command_line=command_line,
            lockdown=lockdown,
            evidence=[
                command_line_evidence,
                lockdown_evidence,
            ],
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

    def _collect_lockdown(
        self,
    ) -> tuple[str | None, EvidenceItem, str | None]:
        source = EvidenceSource(
            path=str(self._LOCKDOWN),
            description="Current kernel lockdown state.",
        )

        try:
            raw_value = self._LOCKDOWN.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()

        except FileNotFoundError:
            error = f"Kernel lockdown interface unavailable: {self._LOCKDOWN}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=source,
                    error=error,
                ),
                error,
            )

        except PermissionError:
            error = f"Permission denied reading kernel lockdown: {self._LOCKDOWN}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        except OSError as exc:
            error = f"Unable to read kernel lockdown {self._LOCKDOWN}: {exc}"

            return (
                None,
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=source,
                    error=error,
                ),
                error,
            )

        active_mode = self._parse_lockdown_state(raw_value)

        return (
            active_mode,
            EvidenceItem(
                key="kernel.lockdown",
                value={
                    "raw": raw_value,
                    "active_mode": active_mode,
                },
                status=EvidenceStatus.AVAILABLE,
                source=source,
            ),
            None,
        )

    @staticmethod
    def _parse_lockdown_state(value: str) -> str | None:
        """Extract the active lockdown mode from the kernel interface."""
        for mode in ("confidentiality", "integrity"):
            if f"[{mode}]" in value:
                return mode

        return None
