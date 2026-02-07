"""
Target and Scope Data Models
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ScopeType(str, Enum):
    """Scope authorization type"""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"


class AuthorizationStatus(str, Enum):
    """Authorization status"""
    AUTHORIZED = "authorized"
    PENDING = "pending"
    DENIED = "denied"
    UNKNOWN = "unknown"


class Target(BaseModel):
    """Target system model"""
    id: Optional[str] = None
    url: str
    name: Optional[str] = None
    description: Optional[str] = None
    scope_type: ScopeType = ScopeType.WHITELIST
    authorization_status: AuthorizationStatus = AuthorizationStatus.UNKNOWN
    authorization_doc: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScopeVerificationRequest(BaseModel):
    """Scope verification request"""
    url: str
    authorization_doc: Optional[str] = None


class ScopeVerificationResponse(BaseModel):
    """Scope verification response"""
    url: str
    is_in_scope: bool
    authorization_status: AuthorizationStatus
    warnings: List[str] = Field(default_factory=list)
    scope_boundaries: List[str] = Field(default_factory=list)
    message: str


class TargetListResponse(BaseModel):
    """Target list response"""
    targets: List[Target]
    total: int
