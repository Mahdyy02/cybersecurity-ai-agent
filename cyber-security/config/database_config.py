"""
Database Configuration
Set your PostgreSQL connection details here or via environment variables
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# PostgreSQL connection settings
# Priority: Environment variable > Config file defaults

def get_database_url() -> str:
    """
    Get PostgreSQL database URL
    
    Returns connection string in format:
    postgresql://username:password@host:port/database
    """
    
    # Try environment variable first
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        return db_url
    
    # Build from individual environment variables or defaults
    db_user = os.getenv('DB_USER', 'postgres')
    db_password = os.getenv('DB_PASSWORD', 'postgres')
    db_host = os.getenv('DB_HOST', '127.0.0.1')  # Use 127.0.0.1 instead of localhost
    db_port = os.getenv('DB_PORT', '5432')
    db_name = os.getenv('DB_NAME', 'cybersecurity')
    
    return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"


# Database settings
DATABASE_CONFIG = {
    'url': get_database_url(),
    'pool_size': 10,
    'max_overflow': 20,
    'pool_pre_ping': True,
    'echo': False  # Set to True for SQL query logging
}

# Cache settings
CACHE_CONFIG = {
    'max_age_days': 3,  # Maximum age of cached data
    'cleanup_days': 30  # Delete records older than this
}

# Connection test settings
TEST_CONFIG = {
    'timeout': 5,  # Connection timeout in seconds
    'retry_attempts': 3
}
