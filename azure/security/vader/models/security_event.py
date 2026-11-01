"""Validated, tenant-scoped synthetic security signals."""
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, StrictBool, field_validator, model_validator

Count = Annotated[int, Field(strict=True, ge=0)]


class LoginDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    failed_attempts: Count = 0


class AuthorizationDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    authorized: StrictBool


class TransferDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    bytes_transferred: Count


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    event_type: Literal["login", "privilege_escalation", "sensitive_resource_access", "data_transfer"]
    actor_identifier: str = Field(min_length=1)
    event_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: IPvAnyAddress | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("actor_identifier")
    @classmethod
    def clean_actor(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("actor_identifier must not be blank")
        return value.strip()

    @field_validator("event_time")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_details(self):
        schema = {"login": LoginDetails, "privilege_escalation": AuthorizationDetails,
                  "sensitive_resource_access": AuthorizationDetails, "data_transfer": TransferDetails}[self.event_type]
        self.details = schema.model_validate(self.details).model_dump()
        return self
