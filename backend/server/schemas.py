"""
Pydantic Schemas for Request/Response Models
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class ChatRequest(BaseModel):
    """Request model for chat endpoint"""
    prompt: str = Field(..., description="User message/prompt")
    currentSite: Optional[str] = Field(None, description="Current site URL if any")
    sessionId: Optional[int] = Field(None, description="Session ID for conversation context")


class SiteInfo(BaseModel):
    """Site information"""
    url: str = Field(..., description="Site URL")
    label: str = Field(..., description="Site display label")


class ChatResponse(BaseModel):
    """Response model for chat endpoint"""
    site: Optional[str] = Field(None, description="Detected or current site URL")
    reply: str = Field(..., description="Agent response message")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class SiteDetail(BaseModel):
    """Detailed site information"""
    id: int
    url: str
    label: str
    created_at: datetime
    last_scan: Optional[datetime] = None
    vulnerability_count: int = 0
    exploit_count: int = 0


class ConversationMessage(BaseModel):
    """Chat message in conversation"""
    role: str = Field(..., description="'user' or 'assistant'")
    content: str = Field(..., description="Message content")
    timestamp: datetime


class SiteListResponse(BaseModel):
    """Response for site list endpoint"""
    sites: List[SiteDetail]


class SiteHistoryResponse(BaseModel):
    """Response for site history endpoint"""
    site_id: int
    url: str
    conversation: List[ConversationMessage]
    vulnerabilities: List[Dict[str, Any]]
    exploits: List[Dict[str, Any]]


class DeleteResponse(BaseModel):
    """Response for delete operations"""
    success: bool
    message: str
