"""Contracts for the permission-gated AWS security agent."""

from typing import Literal

from pydantic import BaseModel, Field


FindingStatus = Literal["pass", "fail", "unavailable", "error"]
Severity = Literal["high", "medium", "low"]


class SecurityFinding(BaseModel):
    finding_id: str
    check_id: str
    service: str
    resource: str
    title: str
    severity: Severity
    status: FindingStatus
    description: str
    risk: str
    current_value: str
    desired_value: str
    remediation: str
    remediable: bool = False
    requires_confirmation: bool = False


class SecurityScanSummary(BaseModel):
    total: int
    passed: int
    failed: int
    unavailable: int
    errors: int
    remediable: int


class SecurityScanResponse(BaseModel):
    scan_id: str
    generated_at: str
    environment: str
    region: str
    scope: str
    remediation_enabled: bool
    summary: SecurityScanSummary
    findings: list[SecurityFinding]


class SecurityRemediationRequest(BaseModel):
    scan_id: str = Field(min_length=1, max_length=128)
    finding_ids: list[str] = Field(min_length=1, max_length=20)
    confirm: bool
    acknowledgement: str = Field(min_length=1, max_length=64)


class SecurityRemediationAction(BaseModel):
    finding_id: str
    service: str
    resource: str
    status: Literal["applied", "failed"]
    message: str


class SecurityRemediationResponse(BaseModel):
    source_scan_id: str
    actions: list[SecurityRemediationAction]
    scan: SecurityScanResponse
