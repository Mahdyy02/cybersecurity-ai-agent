"""
Database Models
Additional models for API-specific data if needed
"""

from datetime import datetime
from typing import Optional, Dict, Any


class SiteSession:
    """Represents an active site analysis session"""
    
    def __init__(self, url: str, label: str):
        self.url = url
        self.label = label
        self.created_at = datetime.now()
        self.messages = []
        self.metadata: Dict[str, Any] = {}
    
    def add_message(self, role: str, content: str):
        """Add a message to the session"""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now()
        })
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            "url": self.url,
            "label": self.label,
            "created_at": self.created_at.isoformat(),
            "messages": self.messages,
            "metadata": self.metadata
        }


# In-memory storage for active sessions (could be moved to Redis/database later)
active_sessions: Dict[str, SiteSession] = {}
