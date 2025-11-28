"""
FastAPI Dependencies
Shared dependencies for dependency injection
"""

import os
from typing import Optional
from functools import lru_cache
from dotenv import load_dotenv
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm.agent import SecurityAgent
from llm.database import DatabaseManager

# Load environment variables
load_dotenv()


@lru_cache()
def get_database_url() -> str:
    """Get database URL from environment"""
    return os.getenv("DATABASE_URL", "sqlite:///./cybersecurity.db")


@lru_cache()
def get_security_agent() -> SecurityAgent:
    """
    Get or create SecurityAgent instance (singleton)
    """
    database_url = get_database_url()
    agent = SecurityAgent(database_url=database_url)
    return agent


def get_db_manager() -> DatabaseManager:
    """
    Get database manager instance
    """
    database_url = get_database_url()
    return DatabaseManager(database_url)
