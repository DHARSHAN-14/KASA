"""Security findings produced by KASA analyzers."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A deterministic security finding."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str
    severity: Severity
    category: str
    evidence_keys: list[str] = Field(default_factory=list)
    recommendation: str | None = None
