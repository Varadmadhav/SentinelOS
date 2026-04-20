"""
models/fraud.py
---------------
Pydantic models for all fraud database entities.
Used for validation, serialisation, and type safety across the entire backend.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Threat severity levels — ordered from lowest to highest."""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def weight(self) -> float:
        """Numeric weight consumed by the scoring engine."""
        return {
            Severity.low: 0.3,
            Severity.medium: 0.5,
            Severity.high: 0.75,
            Severity.critical: 1.0,
        }[self]


class DataSource(str, Enum):
    manual = "manual"
    reported = "reported"
    imported = "imported"
    api = "api"


# ---------------------------------------------------------------------------
# Base entity
# ---------------------------------------------------------------------------


class FraudEntityBase(BaseModel):
    """Common fields shared by every fraud entity type."""

    tags: List[str] = Field(default_factory=list, description="Behavioural tags, e.g. 'otp_scam'")
    severity: Severity = Severity.medium
    reported_count: int = Field(default=0, ge=0)
    added_at: datetime = Field(default_factory=datetime.utcnow)
    source: DataSource = DataSource.manual
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------


class FraudPhoneNumber(FraudEntityBase):
    number: str = Field(..., description="E.164 format, e.g. +919999999999")

    @field_validator("number")
    @classmethod
    def normalise_number(cls, v: str) -> str:
        """Strip spaces/dashes; enforce E.164 prefix."""
        cleaned = v.strip().replace(" ", "").replace("-", "")
        if not cleaned.startswith("+"):
            raise ValueError(f"Phone number must be in E.164 format (start with '+'): {v}")
        return cleaned


# ---------------------------------------------------------------------------
# UPI IDs
# ---------------------------------------------------------------------------


class FraudUPIId(FraudEntityBase):
    upi_id: str = Field(..., description="Full UPI VPA, e.g. scammer@ybl")

    @field_validator("upi_id")
    @classmethod
    def normalise_upi(cls, v: str) -> str:
        """Lowercase and strip whitespace for consistent lookups."""
        return v.strip().lower()


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


class FraudURL(FraudEntityBase):
    url: str = Field(..., description="Full URL including scheme")

    @field_validator("url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        """Lowercase scheme+host; preserve path casing."""
        return v.strip()


# ---------------------------------------------------------------------------
# Lookup result — returned by every db.lookup_* method
# ---------------------------------------------------------------------------


class LookupResult(BaseModel):
    """Uniform response shape from every database lookup."""

    found: bool
    entity_type: str                         # "phone_number" | "upi_id" | "url"
    query: str                               # The normalised value that was looked up
    severity: Optional[Severity] = None
    tags: List[str] = Field(default_factory=list)
    reported_count: int = 0
    source: Optional[DataSource] = None

    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.critical

    @property
    def is_high_or_above(self) -> bool:
        return self.severity in (Severity.high, Severity.critical)