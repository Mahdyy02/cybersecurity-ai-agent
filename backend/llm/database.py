"""
PostgreSQL Database Models and Management
Using SQLAlchemy and Pydantic for security assessment data storage
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Index, text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, Field, validator
import os
import sys
import re
from urllib.parse import urlparse
from pathlib import Path

# Add project root to path to import config
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.database_config import get_database_url

# SQLAlchemy Base
Base = declarative_base()


# ============================================================================
# Data Filtering Utilities
# ============================================================================

def should_filter_record(category: str, key: str, value: str) -> bool:
    """
    Filter out noisy progress/debug lines from CSV data
    
    Args:
        category: CSV category field
        key: CSV key field
        value: CSV value field
    
    Returns:
        True if record should be filtered out (ignored), False if it should be kept
    """
    if not key or not value:
        return True
    
    # Convert to strings for pattern matching
    category_str = str(category)
    key_str = str(key)
    value_str = str(value)
    
    # Filter out ANSI color codes in any field (highest priority)
    if re.search(r'\[3[0-7]m|\[0m|\[\d+m', category_str + key_str + value_str):
        return True
    
    # Filter patterns for noisy data
    noise_patterns = [
        # Progress indicators (key or value)
        r'(scanning|requests|loading).*\d+/\d+',
        
        # Exception messages (key)
        r'^exception$',
        
        # Generic progress counters
        r'^\d+/\d+$',
        
        # Progress indicators as key
        r'^(scanning|requests|loading|progress)$',
    ]
    
    # Value patterns for exceptions
    exception_patterns = [
        r'(timeout|timed out|refused|failed|connection error)',
    ]
    
    # Check key field for noise patterns (case-insensitive)
    for pattern in noise_patterns:
        if re.search(pattern, key_str, re.IGNORECASE):
            return True
    
    # Check if key is "Exception" and value contains error messages
    if re.search(r'^exception$', key_str, re.IGNORECASE):
        for pattern in exception_patterns:
            if re.search(pattern, value_str, re.IGNORECASE):
                return True
    
    # Check value field for noise patterns (less strict)
    value_noise_patterns = [
        r'\d+/\d+$',  # Pure progress counters
    ]
    
    for pattern in value_noise_patterns:
        if re.search(pattern, value_str):
            # Also check if key looks like progress
            if re.search(r'(scanning|request|loading|progress)', key_str, re.IGNORECASE):
                return True
    
    return False


# ============================================================================
# SQLAlchemy ORM Models (Database Tables)
# ============================================================================

class WebsiteInfo(Base):
    """
    Consolidated website information - ONE ROW PER WEBSITE
    All information gathering results stored in JSON columns for flexibility
    """
    __tablename__ = 'website_info'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, unique=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    
    # Target Information
    scheme = Column(String(10), nullable=True)  # http/https
    path = Column(String(2048), nullable=True)
    
    # HTTP Information
    http_headers = Column(JSON, nullable=True)  # All HTTP headers as JSON
    http_status_code = Column(Integer, nullable=True)
    
    # DNS Information
    dns_records = Column(JSON, nullable=True)  # All DNS records as JSON
    ip_addresses = Column(JSON, nullable=True)  # List of IP addresses
    
    # Port Scan Results
    open_ports = Column(JSON, nullable=True)  # List of open ports with services
    total_open_ports = Column(Integer, nullable=True)
    
    # WHOIS Information
    whois_data = Column(JSON, nullable=True)  # WHOIS information as JSON
    registrar = Column(String(255), nullable=True)
    
    # Additional Data (flexible storage)
    additional_info = Column(JSON, nullable=True)  # Any other categorized data
    
    # Metadata
    first_scan = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    scan_count = Column(Integer, default=1, nullable=False)
    
    __table_args__ = (
        Index('idx_website_domain', 'domain'),
        Index('idx_website_updated', 'last_updated'),
    )


# Keep old models for backward compatibility (will be deprecated)
class InfoRecord(Base):
    """DEPRECATED: Information gathering results - use WebsiteInfo instead"""
    __tablename__ = 'info_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    category = Column(String(255), nullable=False)
    key = Column(String(255), nullable=False)
    value = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Composite index for faster queries
    __table_args__ = (
        Index('idx_info_url_timestamp', 'url', 'timestamp'),
        Index('idx_info_category', 'category'),
    )


class VulnerabilityRecord(Base):
    """Vulnerability scan results - matches vulns.csv schema"""
    __tablename__ = 'vulnerability_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    type = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    parameter = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_vuln_url_timestamp', 'url', 'timestamp'),
        Index('idx_vuln_type_severity', 'type', 'severity'),
    )


class ExploitRecord(Base):
    """Exploit validation results - matches exploits.csv schema"""
    __tablename__ = 'exploit_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    type = Column(String(255), nullable=False)
    status = Column(String(100), nullable=False)
    parameter = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    result = Column(Text, nullable=True)
    data_extracted = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_exploit_url_timestamp', 'url', 'timestamp'),
        Index('idx_exploit_type_status', 'type', 'status'),
    )


class ScanMetadata(Base):
    """Metadata about scans for cache management"""
    __tablename__ = 'scan_metadata'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, unique=True, index=True)
    last_info_scan = Column(DateTime, nullable=True)
    last_vuln_scan = Column(DateTime, nullable=True)
    last_exploit_scan = Column(DateTime, nullable=True)
    info_count = Column(Integer, default=0)
    vuln_count = Column(Integer, default=0)
    exploit_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SiteSession(Base):
    """Site analysis sessions - tracks each unique site analyzed"""
    __tablename__ = 'site_sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, unique=True, index=True)
    label = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_session_url', 'url'),
        Index('idx_session_created', 'created_at'),
    )


class ConversationMessage(Base):
    """Conversation messages between user and agent"""
    __tablename__ = 'conversation_messages'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=False, index=True)
    role = Column(String(50), nullable=False)  # 'user' or 'assistant'
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_conversation_session', 'session_id', 'timestamp'),
    )


# ============================================================================
# Pydantic Models (Data Validation)
# ============================================================================

class InfoRecordSchema(BaseModel):
    """Pydantic schema for info records - validates CSV data"""
    category: str = Field(..., alias='Category')
    key: str = Field(..., alias='Key')
    value: Optional[str] = Field(None, alias='Value')
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow, alias='Timestamp')
    
    class Config:
        populate_by_name = True
        
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except:
                return datetime.utcnow()
        return v or datetime.utcnow()


class VulnerabilityRecordSchema(BaseModel):
    """Pydantic schema for vulnerability records"""
    type: str = Field(..., alias='Type')
    severity: str = Field(..., alias='Severity')
    url: str = Field(..., alias='URL')
    parameter: Optional[str] = Field(None, alias='Parameter')
    payload: Optional[str] = Field(None, alias='Payload')
    evidence: Optional[str] = Field(None, alias='Evidence')
    description: Optional[str] = Field(None, alias='Description')
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow, alias='Timestamp')
    
    class Config:
        populate_by_name = True
        
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except:
                return datetime.utcnow()
        return v or datetime.utcnow()


class ExploitRecordSchema(BaseModel):
    """Pydantic schema for exploit records"""
    type: str = Field(..., alias='Type')
    status: str = Field(..., alias='Status')
    url: str = Field(..., alias='URL')
    parameter: Optional[str] = Field(None, alias='Parameter')
    payload: Optional[str] = Field(None, alias='Payload')
    result: Optional[str] = Field(None, alias='Result')
    data_extracted: Optional[str] = Field(None, alias='Data Extracted')
    description: Optional[str] = Field(None, alias='Description')
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow, alias='Timestamp')
    
    class Config:
        populate_by_name = True
        
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except:
                return datetime.utcnow()
        return v or datetime.utcnow()


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    """
    PostgreSQL database manager for security assessment data
    """
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database connection
        
        Args:
            database_url: PostgreSQL connection string
                         Format: postgresql://user:password@host:port/database
                         If None, uses config/database_config.py (reads from .env)
        """
        if database_url is None:
            # Use the proper config system that reads from .env
            database_url = get_database_url()
        
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_size=5,  # Reduced from 10
            max_overflow=10,  # Reduced from 20
            pool_recycle=3600,  # Recycle connections after 1 hour
            echo=False  # Set to True for SQL debugging
        )
        
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        # Test connection on initialization
        try:
            if not self.test_connection():
                print("⚠️  WARNING: PostgreSQL connection failed!")
                print(f"   Connection string: {database_url.split('@')[1] if '@' in database_url else 'unknown'}")
                print("   Please check:")
                print("   1. PostgreSQL is running (net start postgresql-x64-15)")
                print("   2. Database 'cybersecurity' exists")
                print("   3. Username/password in .env are correct")
                print("   4. Port 5432 is accessible")
                print(f"\n   Current .env settings:")
                print(f"   DB_PASSWORD: {os.getenv('DB_PASSWORD', 'not set')}")
                print(f"   DB_HOST: {os.getenv('DB_HOST', 'not set')}")
        except Exception as e:
            print(f"⚠️  WARNING: Database initialization error: {str(e)}")
            print("   Data will NOT be saved to database!")
    
    def create_tables(self, drop_existing: bool = False):
        """
        Create all tables if they don't exist
        
        Args:
            drop_existing: If True, drop existing tables first (careful!)
        """
        if drop_existing:
            Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine, checkfirst=True)
    
    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()
    
    def test_connection(self) -> bool:
        """
        Test database connection
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            session = self.get_session()
            session.execute(text("SELECT 1"))
            session.close()
            return True
        except Exception:
            return False
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent storage"""
        # Ensure url is a string (handle bytes from some database drivers)
        if isinstance(url, bytes):
            url = url.decode('utf-8')
        
        # Convert to string if needed
        url = str(url)
        
        parsed = urlparse(url)
        # Remove trailing slash for consistency
        path = parsed.path.rstrip('/') if parsed.path else ''
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    
    # ========================================================================
    # NEW: Consolidated Website Info (ONE ROW PER WEBSITE)
    # ========================================================================
    
    def save_website_info(self, url: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Save website information in consolidated format (one row per website)
        Automatically filters out noisy progress/debug lines
        
        Args:
            url: Target URL
            records: List of dictionaries from info.csv
            
        Returns:
            Dictionary with statistics about saved data
        """
        url = self._normalize_url(url)
        parsed = urlparse(url)
        domain = parsed.netloc
        
        session = self.get_session()
        
        try:
            # Filter out noisy records
            filtered_records = [
                r for r in records 
                if not should_filter_record(
                    r.get('Category', ''),
                    r.get('Key', ''),
                    r.get('Value', '')
                )
            ]
            
            # Organize data by category
            organized_data = self._organize_info_data(filtered_records)
            
            # Check if website already exists
            website = session.query(WebsiteInfo).filter(
                WebsiteInfo.url == url
            ).first()
            
            if website:
                # Update existing record
                website.http_headers = organized_data.get('http_headers')
                website.http_status_code = organized_data.get('http_status_code')
                website.dns_records = organized_data.get('dns_records')
                website.ip_addresses = organized_data.get('ip_addresses')
                website.open_ports = organized_data.get('open_ports')
                website.total_open_ports = organized_data.get('total_open_ports')
                website.whois_data = organized_data.get('whois_data')
                website.registrar = organized_data.get('registrar')
                website.additional_info = organized_data.get('additional_info')
                website.last_updated = datetime.utcnow()
                website.scan_count += 1
            else:
                # Create new record
                website = WebsiteInfo(
                    url=url,
                    domain=domain,
                    scheme=parsed.scheme,
                    path=parsed.path or '/',
                    http_headers=organized_data.get('http_headers'),
                    http_status_code=organized_data.get('http_status_code'),
                    dns_records=organized_data.get('dns_records'),
                    ip_addresses=organized_data.get('ip_addresses'),
                    open_ports=organized_data.get('open_ports'),
                    total_open_ports=organized_data.get('total_open_ports'),
                    whois_data=organized_data.get('whois_data'),
                    registrar=organized_data.get('registrar'),
                    additional_info=organized_data.get('additional_info'),
                    scan_count=1
                )
                session.add(website)
            
            session.commit()
            
            return {
                'total_records': len(records),
                'filtered_records': len(records) - len(filtered_records),
                'saved_records': len(filtered_records),
                'is_update': website.scan_count > 1
            }
            
        except Exception as e:
            session.rollback()
            print(f"❌ ERROR: Failed to save to database: {str(e)}")
            print(f"   Error type: {type(e).__name__}")
            if "authentication" in str(e).lower() or "password" in str(e).lower():
                print("   → This is a PostgreSQL authentication error")
                print("   → Check your database password in DATABASE_URL")
            raise e
        finally:
            session.close()
    
    def _organize_info_data(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Organize raw CSV records into structured JSON format
        
        Args:
            records: Filtered list of info records
            
        Returns:
            Dictionary with organized data
        """
        organized = {
            'http_headers': {},
            'http_status_code': None,
            'dns_records': {},
            'ip_addresses': [],
            'open_ports': [],
            'total_open_ports': 0,
            'whois_data': {},
            'registrar': None,
            'additional_info': {}
        }
        
        for record in records:
            category = record.get('Category', '')
            key = record.get('Key', '')
            value = record.get('Value', '')
            
            # HTTP Headers
            if category == 'HTTP Headers':
                organized['http_headers'][key] = value
            
            # HTTP Response
            elif category == 'HTTP Response' and key == 'Status Code':
                try:
                    organized['http_status_code'] = int(value)
                except:
                    pass
            
            # DNS Records
            elif category == 'DNS Records':
                if key not in organized['dns_records']:
                    organized['dns_records'][key] = []
                organized['dns_records'][key].append(value)
                
                # Extract IP addresses
                if 'A Record' in key or 'AAAA Record' in key:
                    if value not in organized['ip_addresses']:
                        organized['ip_addresses'].append(value)
            
            # Open Ports
            elif category == 'Open Ports':
                port_info = {'port': key, 'service': value}
                organized['open_ports'].append(port_info)
            
            # Port Scan Summary
            elif category == 'Port Scan Summary':
                if key == 'Total Open Ports':
                    try:
                        organized['total_open_ports'] = int(value)
                    except:
                        pass
            
            # WHOIS/Registrar Info
            elif 'Registrar' in category or 'WHOIS' in category.upper():
                organized['whois_data'][key] = value
                if 'Registrar' in key and 'Abuse' not in key:
                    organized['registrar'] = value
            
            # Target Information
            elif category == 'Target Information':
                if key not in ['URL', 'Domain', 'Scheme', 'Path']:
                    if 'target_info' not in organized['additional_info']:
                        organized['additional_info']['target_info'] = {}
                    organized['additional_info']['target_info'][key] = value
            
            # Everything else goes into additional_info
            else:
                if category not in organized['additional_info']:
                    organized['additional_info'][category] = {}
                organized['additional_info'][category][key] = value
        
        return organized
    
    def get_website_info(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get consolidated website information
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with all website information or None if not found
        """
        import json
        
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            website = session.query(WebsiteInfo).filter(
                WebsiteInfo.url == url
            ).first()
            
            if not website:
                return None
            
            # Helper to deserialize JSON fields (handles dict, bytes, and str)
            def deserialize_json(value):
                if value is None:
                    return None
                
                # Already a Python object (dict/list)
                if isinstance(value, (dict, list)):
                    return value
                
                # Handle bytes (from some database drivers)
                if isinstance(value, bytes):
                    try:
                        decoded = value.decode('utf-8')
                        return json.loads(decoded)
                    except Exception as e:
                        print(f"[DB] Error decoding bytes to JSON: {e}")
                        return None
                
                # Handle string (might be JSON string or plain text)
                if isinstance(value, str):
                    # Empty string
                    if not value.strip():
                        return None
                    
                    # Try to parse as JSON
                    try:
                        return json.loads(value)
                    except json.JSONDecodeError:
                        # Not JSON, return as plain string (shouldn't happen with JSON columns)
                        print(f"[DB] Value is not valid JSON, returning as string: {value[:50]}...")
                        return value
                    except Exception as e:
                        print(f"[DB] Error parsing string as JSON: {e}")
                        return None
                
                # Unknown type, return as-is
                print(f"[DB] Unknown type for JSON field: {type(value)}")
                return value
            
            return {
                'url': website.url,
                'domain': website.domain,
                'scheme': website.scheme,
                'path': website.path,
                'http_headers': deserialize_json(website.http_headers),
                'http_status_code': website.http_status_code,
                'dns_records': deserialize_json(website.dns_records),
                'ip_addresses': deserialize_json(website.ip_addresses),
                'open_ports': deserialize_json(website.open_ports),
                'total_open_ports': website.total_open_ports,
                'whois_data': deserialize_json(website.whois_data),
                'registrar': website.registrar,
                'additional_info': deserialize_json(website.additional_info),
                'first_scan': website.first_scan.isoformat(),
                'last_updated': website.last_updated.isoformat(),
                'scan_count': website.scan_count
            }
            
        finally:
            session.close()
    
    # ========================================================================
    # OLD: Info Records (Deprecated - kept for backward compatibility)
    # ========================================================================
    
    def save_info_records(self, url: str, records: List[Dict[str, Any]]) -> int:
        """
        DEPRECATED: Save information gathering results (use save_website_info instead)
        Now includes automatic filtering of noisy progress/debug lines
        
        Args:
            url: Target URL
            records: List of dictionaries matching info.csv schema
            
        Returns:
            Number of records saved (after filtering)
        """
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            count = 0
            for record in records:
                # Filter out noisy records
                if should_filter_record(
                    record.get('Category', ''),
                    record.get('Key', ''),
                    record.get('Value', '')
                ):
                    continue  # Skip this noisy record
                
                # Validate with Pydantic
                validated = InfoRecordSchema(**record)
                
                # Create ORM object
                db_record = InfoRecord(
                    url=url,
                    category=validated.category,
                    key=validated.key,
                    value=validated.value,
                    timestamp=validated.timestamp
                )
                session.add(db_record)
                count += 1
            
            # Update metadata
            self._update_scan_metadata(session, url, 'info', count)
            
            session.commit()
            return count
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_info_records(self, url: str, max_age_days: int = 3) -> List[Dict[str, Any]]:
        """
        Get cached information records for a URL
        
        Args:
            url: Target URL
            max_age_days: Maximum age of cached data in days
            
        Returns:
            List of dictionaries with info records
        """
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
            
            records = session.query(InfoRecord).filter(
                InfoRecord.url == url,
                InfoRecord.timestamp >= cutoff_date
            ).order_by(InfoRecord.timestamp.desc()).all()
            
            return [
                {
                    'Category': r.category,
                    'Key': r.key,
                    'Value': r.value,
                    'Timestamp': r.timestamp.isoformat()
                }
                for r in records
            ]
            
        finally:
            session.close()
    
    # ========================================================================
    # Vulnerability Records
    # ========================================================================
    
    def save_vulnerability_records(self, url: str, records: List[Dict[str, Any]]) -> int:
        """Save vulnerability scan results"""
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            count = 0
            for record in records:
                # Validate with Pydantic
                validated = VulnerabilityRecordSchema(**record)
                
                # Create ORM object
                db_record = VulnerabilityRecord(
                    url=self._normalize_url(validated.url),
                    type=validated.type,
                    severity=validated.severity,
                    parameter=validated.parameter,
                    payload=validated.payload,
                    evidence=validated.evidence,
                    description=validated.description,
                    timestamp=validated.timestamp
                )
                session.add(db_record)
                count += 1
            
            # Update metadata
            self._update_scan_metadata(session, url, 'vuln', count)
            
            session.commit()
            return count
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_vulnerability_records(self, url: str, max_age_days: int = 3, severity_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get cached vulnerability records for a URL
        
        Args:
            url: Target URL to query
            max_age_days: Maximum age of records in days
            severity_filter: List of severity levels to include (e.g., ['High', 'Medium'])
                           If None, returns all severities
        
        Returns:
            List of vulnerability records matching criteria
        """
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
            
            query = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.url.like(f"{url}%"),
                VulnerabilityRecord.timestamp >= cutoff_date
            )
            
            # Apply severity filter if specified
            if severity_filter:
                query = query.filter(VulnerabilityRecord.severity.in_(severity_filter))
            
            records = query.order_by(VulnerabilityRecord.timestamp.desc()).all()
            
            return [
                {
                    'Type': r.type,
                    'Severity': r.severity,
                    'URL': r.url,
                    'Parameter': r.parameter,
                    'Payload': r.payload,
                    'Evidence': r.evidence,
                    'Description': r.description,
                    'Timestamp': r.timestamp.isoformat()
                }
                for r in records
            ]
            
        finally:
            session.close()
    
    # ========================================================================
    # Exploit Records
    # ========================================================================
    
    def save_exploit_records(self, url: str, records: List[Dict[str, Any]]) -> int:
        """Save exploit validation results"""
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            count = 0
            for record in records:
                # Validate with Pydantic
                validated = ExploitRecordSchema(**record)
                
                # Create ORM object
                db_record = ExploitRecord(
                    url=self._normalize_url(validated.url),
                    type=validated.type,
                    status=validated.status,
                    parameter=validated.parameter,
                    payload=validated.payload,
                    result=validated.result,
                    data_extracted=validated.data_extracted,
                    description=validated.description,
                    timestamp=validated.timestamp
                )
                session.add(db_record)
                count += 1
            
            # Update metadata
            self._update_scan_metadata(session, url, 'exploit', count)
            
            session.commit()
            return count
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_exploit_records(self, url: str, max_age_days: int = 3) -> List[Dict[str, Any]]:
        """Get cached exploit records for a URL"""
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
            
            records = session.query(ExploitRecord).filter(
                ExploitRecord.url.like(f"{url}%"),
                ExploitRecord.timestamp >= cutoff_date
            ).order_by(ExploitRecord.timestamp.desc()).all()
            
            return [
                {
                    'Type': r.type,
                    'Status': r.status,
                    'URL': r.url,
                    'Parameter': r.parameter,
                    'Payload': r.payload,
                    'Result': r.result,
                    'Data Extracted': r.data_extracted,
                    'Description': r.description,
                    'Timestamp': r.timestamp.isoformat()
                }
                for r in records
            ]
            
        finally:
            session.close()
    
    # ========================================================================
    # Metadata Management
    # ========================================================================
    
    def _update_scan_metadata(self, session: Session, url: str, scan_type: str, count: int):
        """Update scan metadata"""
        metadata = session.query(ScanMetadata).filter(
            ScanMetadata.url == url
        ).first()
        
        if not metadata:
            metadata = ScanMetadata(url=url)
            session.add(metadata)
        
        if scan_type == 'info':
            metadata.last_info_scan = datetime.utcnow()
            metadata.info_count = count
        elif scan_type == 'vuln':
            metadata.last_vuln_scan = datetime.utcnow()
            metadata.vuln_count = count
        elif scan_type == 'exploit':
            metadata.last_exploit_scan = datetime.utcnow()
            metadata.exploit_count = count
    
    def get_scan_metadata(self, url: str) -> Optional[Dict[str, Any]]:
        """Get scan metadata for a URL"""
        url = self._normalize_url(url)
        session = self.get_session()
        
        try:
            metadata = session.query(ScanMetadata).filter(
                ScanMetadata.url == url
            ).first()
            
            if metadata:
                return {
                    'url': metadata.url,
                    'last_info_scan': metadata.last_info_scan.isoformat() if metadata.last_info_scan else None,
                    'last_vuln_scan': metadata.last_vuln_scan.isoformat() if metadata.last_vuln_scan else None,
                    'last_exploit_scan': metadata.last_exploit_scan.isoformat() if metadata.last_exploit_scan else None,
                    'info_count': metadata.info_count,
                    'vuln_count': metadata.vuln_count,
                    'exploit_count': metadata.exploit_count,
                    'updated_at': metadata.updated_at.isoformat()
                }
            
            return None
            
        finally:
            session.close()
    
    def check_cache_valid(self, url: str, scan_type: str, max_age_days: int = 3) -> bool:
        """
        Check if cached data is still valid
        
        Args:
            url: Target URL
            scan_type: 'info', 'vuln', or 'exploit'
            max_age_days: Maximum age in days
            
        Returns:
            True if cache is valid, False otherwise
        """
        metadata = self.get_scan_metadata(url)
        
        if not metadata:
            return False
        
        field_map = {
            'info': 'last_info_scan',
            'vuln': 'last_vuln_scan',
            'exploit': 'last_exploit_scan'
        }
        
        last_scan = metadata.get(field_map.get(scan_type))
        
        if not last_scan:
            return False
        
        last_scan_date = datetime.fromisoformat(last_scan)
        return (datetime.utcnow() - last_scan_date) < timedelta(days=max_age_days)
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def clear_old_records(self, days: int = 30):
        """Delete records older than specified days"""
        session = self.get_session()
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Delete old records
            session.query(InfoRecord).filter(
                InfoRecord.timestamp < cutoff_date
            ).delete()
            
            session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.timestamp < cutoff_date
            ).delete()
            
            session.query(ExploitRecord).filter(
                ExploitRecord.timestamp < cutoff_date
            ).delete()
            
            session.commit()
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get database statistics"""
        session = self.get_session()
        
        try:
            return {
                'info_records': session.query(InfoRecord).count(),
                'vulnerability_records': session.query(VulnerabilityRecord).count(),
                'exploit_records': session.query(ExploitRecord).count(),
                'scanned_urls': session.query(ScanMetadata).count(),
                'site_sessions': session.query(SiteSession).count(),
                'conversation_messages': session.query(ConversationMessage).count()
            }
        finally:
            session.close()
    
    # ========================================================================
    # Site Session Management
    # ========================================================================
    
    def create_or_get_session(self, url: str, label: str = None) -> Dict[str, Any]:
        """
        Create a new site session or get existing one
        
        Args:
            url: Site URL
            label: Display label (defaults to domain from URL)
        
        Returns:
            Session data dictionary
        """
        session = self.get_session()
        
        try:
            # Normalize URL
            normalized_url = self._normalize_url(url)
            
            # Check if session exists
            site_session = session.query(SiteSession).filter(
                SiteSession.url == normalized_url
            ).first()
            
            if site_session:
                # Update last activity
                site_session.last_activity = datetime.utcnow()
                session.commit()
            else:
                # Create new session
                if not label:
                    # Extract label from URL
                    parsed = urlparse(normalized_url)
                    label = parsed.netloc or normalized_url
                
                site_session = SiteSession(
                    url=normalized_url,
                    label=label
                )
                session.add(site_session)
                session.commit()
                session.refresh(site_session)
            
            return {
                'id': site_session.id,
                'url': site_session.url,
                'label': site_session.label,
                'created_at': site_session.created_at,
                'last_activity': site_session.last_activity
            }
        
        except Exception as e:
            session.rollback()
            print(f"[!] Error creating/getting session: {str(e)}")
            raise e
        finally:
            session.close()
    
    def get_site_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific session by ID"""
        db_session = self.SessionLocal()
        
        try:
            site_session = db_session.query(SiteSession).filter(
                SiteSession.id == session_id
            ).first()
            
            if not site_session:
                return None
            
            return {
                'id': site_session.id,
                'url': site_session.url,
                'label': site_session.label,
                'created_at': site_session.created_at,
                'last_activity': site_session.last_activity
            }
        finally:
            db_session.close()
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all site sessions"""
        db_session = self.get_session()
        
        try:
            sessions = db_session.query(SiteSession).order_by(
                SiteSession.last_activity.desc()
            ).all()
            
            return [
                {
                    'id': s.id,
                    'url': s.url,
                    'label': s.label,
                    'created_at': s.created_at,
                    'last_activity': s.last_activity
                }
                for s in sessions
            ]
        finally:
            db_session.close()
    
    def delete_session(self, session_id: int) -> bool:
        """
        Delete a site session and all associated data
        
        Args:
            session_id: Session ID to delete
        
        Returns:
            True if successful, False otherwise
        """
        db_session = self.get_session()
        
        try:
            # Get the session
            site_session = db_session.query(SiteSession).filter(
                SiteSession.id == session_id
            ).first()
            
            if not site_session:
                return False
            
            url = site_session.url
            
            # Delete conversation messages
            db_session.query(ConversationMessage).filter(
                ConversationMessage.session_id == session_id
            ).delete()
            
            # Delete vulnerability records for this URL
            db_session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.url == url
            ).delete()
            
            # Delete exploit records for this URL
            db_session.query(ExploitRecord).filter(
                ExploitRecord.url == url
            ).delete()
            
            # Delete info records for this URL
            db_session.query(InfoRecord).filter(
                InfoRecord.url == url
            ).delete()
            
            # Delete website info
            db_session.query(WebsiteInfo).filter(
                WebsiteInfo.url == url
            ).delete()
            
            # Delete scan metadata
            db_session.query(ScanMetadata).filter(
                ScanMetadata.url == url
            ).delete()
            
            # Delete the session itself
            db_session.delete(site_session)
            
            db_session.commit()
            return True
        
        except Exception as e:
            db_session.rollback()
            print(f"[!] Error deleting session: {str(e)}")
            return False
        finally:
            db_session.close()
    
    # ========================================================================
    # Conversation Management
    # ========================================================================
    
    def save_conversation_message(self, session_id: int, role: str, content: str):
        """
        Save a conversation message
        
        Args:
            session_id: Site session ID
            role: 'user' or 'assistant'
            content: Message content
        """
        db_session = self.get_session()
        
        try:
            message = ConversationMessage(
                session_id=session_id,
                role=role,
                content=content
            )
            db_session.add(message)
            
            # Update session last activity
            site_session = db_session.query(SiteSession).filter(
                SiteSession.id == session_id
            ).first()
            
            if site_session:
                site_session.last_activity = datetime.utcnow()
            
            db_session.commit()
        
        except Exception as e:
            db_session.rollback()
            print(f"[!] Error saving conversation message: {str(e)}")
            raise e
        finally:
            db_session.close()
    
    def get_conversation_history(self, session_id: int) -> List[Dict[str, Any]]:
        """
        Get conversation history for a session
        
        Args:
            session_id: Site session ID
        
        Returns:
            List of messages
        """
        db_session = self.get_session()
        
        try:
            messages = db_session.query(ConversationMessage).filter(
                ConversationMessage.session_id == session_id
            ).order_by(ConversationMessage.timestamp.asc()).all()
            
            return [
                {
                    'role': msg.role,
                    'content': msg.content,
                    'timestamp': msg.timestamp
                }
                for msg in messages
            ]
        finally:
            db_session.close()
    
    def get_session_results(self, session_id: int, result_type: str) -> List[Dict[str, Any]]:
        """
        Get vulnerability or exploit results for a session
        
        Args:
            session_id: Site session ID
            result_type: 'vulnerability' or 'exploit'
        
        Returns:
            List of results
        """
        db_session = self.get_session()
        
        try:
            # Get the session to get URL
            site_session = db_session.query(SiteSession).filter(
                SiteSession.id == session_id
            ).first()
            
            if not site_session:
                return []
            
            url = site_session.url
            
            if result_type == 'vulnerability':
                records = db_session.query(VulnerabilityRecord).filter(
                    VulnerabilityRecord.url == url
                ).order_by(VulnerabilityRecord.timestamp.desc()).all()
                
                return [
                    {
                        'type': r.type,
                        'severity': r.severity,
                        'url': r.url,
                        'parameter': r.parameter,
                        'payload': r.payload,
                        'evidence': r.evidence,
                        'description': r.description,
                        'timestamp': r.timestamp
                    }
                    for r in records
                ]
            
            elif result_type == 'exploit':
                records = db_session.query(ExploitRecord).filter(
                    ExploitRecord.url == url
                ).order_by(ExploitRecord.timestamp.desc()).all()
                
                return [
                    {
                        'type': r.type,
                        'status': r.status,
                        'url': r.url,
                        'parameter': r.parameter,
                        'payload': r.payload,
                        'result': r.result,
                        'data_extracted': r.data_extracted,
                        'description': r.description,
                        'timestamp': r.timestamp
                    }
                    for r in records
                ]
            
            return []
        finally:
            db_session.close()


# ============================================================================
# Convenience Functions
# ============================================================================

def get_database() -> DatabaseManager:
    """Get database manager instance"""
    return DatabaseManager()


def init_database(database_url: Optional[str] = None):
    """Initialize database and create tables"""
    db = DatabaseManager(database_url)
    db.create_tables()
    return db


# Example usage
if __name__ == '__main__':
    # Initialize database
    db = init_database()
    
    print("Database initialized successfully!")
    print(f"Statistics: {db.get_statistics()}")
