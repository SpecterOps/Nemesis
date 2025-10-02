from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

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
    category: Optional[str] = Field(None, description="Finding category")
    severity: Optional[Union[int, str]] = Field(None, description="Finding severity level (0-10 or string)")
    object_id: str = Field(..., description="Object storage ID")
    data: List[str] = Field(..., description="Finding data payload")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Raw finding data")
    file_path: str = Field(..., description="Path of the file associated with finding")

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        if v is None:
            return v

        try:
            severity_int = int(v)
        except (ValueError, TypeError):
            raise ValueError(f"Severity must be convertible to integer, got: {v}")

        if not 0 <= severity_int <= 10:
            raise ValueError(f"Severity must be between 0 and 10, got: {severity_int}")

        return severity_int

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
        ...,
        description="Triage decision - MUST be exactly one of: true_positive, false_positive, needs_review"
    )
    explanation: str = Field(..., description="Accurate but concise 1 sentence explanation for the decision")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score 0-1.0")
    true_positive_context: Optional[str] = Field(None, description="Context/risk for true_positive decisions. Only required for true_positive findings.")

class CredentialWithContext(BaseModel):
    """A credential with its surrounding textual context."""
    credential: str = Field(..., description="The extracted credential/password")
    context: str = Field(..., description="Surrounding textual context for the credential")

class CredentialAnalysisResponse(BaseModel):
    """Response from credential analysis agent."""
    credentials: List[CredentialWithContext] = Field(default_factory=list, description="List of extracted credentials with their surrounding context")

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
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence score 0-1.0 (optional)")
    true_positive_context: Optional[str] = Field(None, description="Context/risk for true_positive decisions")
    success: bool = Field(..., description="Whether the triage process completed successfully")
