from enum import Enum
from typing import Any, Literal, Union

from pydantic import BaseModel, Field, field_validator


class TriageCategory(str, Enum):
    """Triage decision categories"""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    NOT_TRIAGED = "not_triaged"
    ERROR = "error"


class TriageDecision(BaseModel):
    """Schema for LLM triage decision response"""

    decision: str = Field(..., description="Triage decision: true_positive, false_positive, or needs_review")
    explanation: str = Field(..., description="One sentence explaining the reasoning for this decision")


class TriageRequest(BaseModel):
    """Schema for triage workflow input"""

    finding_id: int = Field(..., description="Unique finding identifier")
    finding_name: str = Field(..., description="Name/type of the finding")
    category: str | None = Field(None, description="Finding category")
    severity: Union[int, str] | None = Field(None, description="Finding severity level (0-10 or string)")
    object_id: str = Field(..., description="Object storage ID")
    origin_type: str | None = Field(None, description="Type of the finding's origin")
    origin_name: str | None = Field(None, description="Name of the finding's origin")
    data: list[str] = Field(..., description="Finding data payload")
    raw_data: dict[str, Any] | None = Field(None, description="Raw finding data")
    file_path: str = Field(..., description="Path of the file associated with finding")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v is None:
            return v

        try:
            severity_int = int(v)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Severity must be convertible to integer, got: {v}") from e

        if not 0 <= severity_int <= 10:
            raise ValueError(f"Severity must be between 0 and 10, got: {severity_int}")

        return severity_int


class NoseyParkerLocation(BaseModel):
    """Schema for location information in Nosey Parker findings"""

    line: int = Field(..., description="Line number where the match was found")
    column: int = Field(..., description="Column number where the match was found")


class NoseyParkerMatch(BaseModel):
    """Schema for a Nosey Parker match"""

    snippet: str = Field(..., description="Portion of text around where the match was found")
    location: NoseyParkerLocation = Field(..., description="Location of the match in the file")
    file_path: str | None = Field(None, description="Path to the file containing the match")
    rule_name: str = Field(..., description="Name of the detection rule that triggered")
    rule_type: str = Field(..., description="Type/category of the detection rule")
    git_commit: str | None = Field(None, description="Git commit hash where this was found")
    matched_content: str = Field(..., description="The actual content that matched the rule")


class NoseyParkerData(BaseModel):
    """Schema for Nosey Parker finding data"""

    match: NoseyParkerMatch = Field(..., description="Match information from Nosey Parker")


class JWTAnalysis(BaseModel):
    """Schema for JWT-specific analysis"""

    is_expired: bool = Field(..., description="Whether the JWT is expired")
    has_expiry_conflict: bool = Field(False, description="Whether there's conflicting expiry info")
    is_sample_data: bool = Field(False, description="Whether this appears to be sample/test data")
    decision: TriageCategory = Field(..., description="Triage decision for JWT")


class ValidateRequest(BaseModel):
    """Request for validation agent"""

    file_path: str = Field(..., description="Path of the file being analyzed")
    summary: str = Field(..., description="Security finding summary to validate")


class ValidateResponse(BaseModel):
    """Response from validation agent with strict decision values."""

    decision: Literal["true_positive", "false_positive", "needs_review"] = Field(
        ..., description="Triage decision - MUST be exactly one of: true_positive, false_positive, needs_review"
    )
    explanation: str = Field(..., description="Accurate but concise 1 sentence explanation for the decision")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score 0-1.0")
    true_positive_context: str | None = Field(
        None, description="Context/risk for true_positive decisions. Only required for true_positive findings."
    )


class CredentialWithContext(BaseModel):
    """A credential with its surrounding textual context."""

    credential: str = Field(..., description="The extracted credential/password")
    context: str = Field(..., description="Surrounding textual context for the credential")


class CredentialAnalysisResponse(BaseModel):
    """Response from credential analysis agent."""

    credentials: list[CredentialWithContext] = Field(
        default_factory=list, description="List of extracted credentials with their surrounding context"
    )


class SummaryResponse(BaseModel):
    """Response from text summarization agent."""

    summary: str = Field(..., description="Generated summary of the text content")


class TranslationResponse(BaseModel):
    """Response from text translation agent."""

    translated_text: str = Field(..., description="Translated text content in the target language")


class DotNetAnalysisResponse(BaseModel):
    """Response from .NET analysis agent."""

    analysis: str = Field(..., description="Detailed analysis of the .NET assembly")


class TriageResult(BaseModel):
    """Schema for the result returned by finding_triage_workflow()"""

    finding_id: int = Field(..., description="ID of the finding that was triaged")
    decision: str = Field(..., description="Triage decision made")
    explanation: str = Field(..., description="Explanation for the triage decision")
    confidence: float | None = Field(None, ge=0.0, le=1.0, description="Confidence score 0-1.0 (optional)")
    true_positive_context: str | None = Field(None, description="Context/risk for true_positive decisions")
    success: bool = Field(..., description="Whether the triage process completed successfully")
