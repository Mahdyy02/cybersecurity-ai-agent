# PostgreSQL Migration Summary

## Changes Made

This document summarizes the migration from file-based storage to PostgreSQL database.

## New Files Created

### 1. `llm/database.py` (500+ lines)
**Complete PostgreSQL database management system**

**SQLAlchemy ORM Models:**
- `InfoRecord` - Information gathering results table
- `VulnerabilityRecord` - Vulnerability scan results table
- `ExploitRecord` - Exploit validation results table
- `ScanMetadata` - Scan history and cache metadata

**Pydantic Validation Schemas:**
- `InfoRecordSchema` - Validates info CSV data
- `VulnerabilityRecordSchema` - Validates vulnerability CSV data
- `ExploitRecordSchema` - Validates exploit CSV data

**DatabaseManager Class:**
- `save_info_records()` - Save info gathering results
- `get_info_records()` - Get cached info with TTL
- `save_vulnerability_records()` - Save vulnerability scan results
- `get_vulnerability_records()` - Get cached vulnerabilities
- `save_exploit_records()` - Save exploit validation results
- `get_exploit_records()` - Get cached exploits
- `get_scan_metadata()` - Get scan history for URL
- `check_cache_valid()` - Validate cache age (3 days)
- `clear_old_records()` - Cleanup old data
- `get_statistics()` - Database statistics

**Features:**
- Automatic timestamp handling
- URL normalization
- Composite indexes for performance
- Connection pooling (10 connections, 20 max overflow)
- 3-day cache TTL validation
- Transaction management with rollback

### 2. `config/database_config.py`
**Database configuration management**

- `get_database_url()` - Build connection string from env vars
- `DATABASE_CONFIG` - Pool size, timeout, echo settings
- `CACHE_CONFIG` - Cache TTL and cleanup settings
- `TEST_CONFIG` - Connection test parameters

Environment variable support:
- `DATABASE_URL` - Full connection string (priority)
- `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `DB_NAME` - Individual settings

### 3. `setup_database.py`
**Database initialization and management CLI**

Commands:
- `setup` - Create tables and initialize database
- `test` - Test database connection
- `stats` - Show record counts and statistics
- `info --url <url>` - Show scan metadata for URL
- `cleanup --days <n>` - Delete records older than N days

### 4. `.env.example`
**Environment configuration template**

Contains examples for:
- PostgreSQL connection settings
- OpenRouter API key
- Cache configuration

### 5. `docs/DATABASE_SETUP.md`
**Comprehensive database setup guide**

Covers:
- PostgreSQL installation (Windows/Linux/macOS)
- Database creation
- Connection configuration
- Schema documentation
- Usage examples
- Management commands
- Caching strategy
- Performance optimization
- Troubleshooting
- Migration guide
- Security best practices

### 6. `import_csv_to_db.py`
**CSV to PostgreSQL migration tool**

- `import_csv_file()` - Import single CSV file
- `import_results_folder()` - Import entire results folder
- Command-line interface for batch imports

Usage:
```bash
# Import single file
python import_csv_to_db.py --file results/info.csv --type info --url https://example.com

# Import entire folder
python import_csv_to_db.py --folder results --url https://example.com
```

## Modified Files

### 1. `llm/agent.py`
**Replaced file-based SecurityDatabase with PostgreSQL**

**Removed:**
- `SecurityDatabase` class (file-based storage)
- JSON file operations
- Manual timestamp checking

**Changed:**
```python
# OLD
self.db = SecurityDatabase()
db_info = self.db.get_info(url)
self.db.save_info(url, data)

# NEW
self.db = DatabaseManager(database_url)
db_info = self.db.get_info_records(url)
self.db.save_info_records(url, data)
```

**Updated Methods:**
- `__init__()` - Now accepts `database_url` parameter
- `_run_info_gathering()` - Saves to PostgreSQL with `save_info_records()`
- `_run_vulnerability_scan()` - Saves to PostgreSQL with `save_vulnerability_records()`
- `_run_exploit_validation()` - Saves to PostgreSQL with `save_exploit_records()`
- `_display_info()` - Reads from PostgreSQL with metadata
- `_display_vulnerabilities()` - Reads from PostgreSQL with metadata
- `process_user_message()` - Uses `check_cache_valid()` for 3-day TTL

**Benefits:**
- Automatic cache validation
- Better concurrency (no file locking)
- Efficient queries with indexes
- Transaction safety

### 2. `requirements.txt`
**Added PostgreSQL dependencies**

New packages:
```
sqlalchemy==2.0.23      # ORM framework
psycopg2-binary==2.9.9  # PostgreSQL driver
pydantic==2.5.2         # Data validation
```

## Database Schema

### Tables Created

#### info_records
```sql
CREATE TABLE info_records (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    category VARCHAR(255) NOT NULL,
    key VARCHAR(255) NOT NULL,
    value TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_info_url_timestamp ON info_records(url, timestamp);
CREATE INDEX idx_info_category ON info_records(category);
```

#### vulnerability_records
```sql
CREATE TABLE vulnerability_records (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    parameter VARCHAR(255),
    payload TEXT,
    evidence TEXT,
    description TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vuln_url_timestamp ON vulnerability_records(url, timestamp);
CREATE INDEX idx_vuln_type_severity ON vulnerability_records(type, severity);
```

#### exploit_records
```sql
CREATE TABLE exploit_records (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) NOT NULL,
    type VARCHAR(255) NOT NULL,
    status VARCHAR(100) NOT NULL,
    parameter VARCHAR(255),
    payload TEXT,
    result TEXT,
    data_extracted TEXT,
    description TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_exploit_url_timestamp ON exploit_records(url, timestamp);
CREATE INDEX idx_exploit_type_status ON exploit_records(type, status);
```

#### scan_metadata
```sql
CREATE TABLE scan_metadata (
    id SERIAL PRIMARY KEY,
    url VARCHAR(2048) UNIQUE NOT NULL,
    last_info_scan TIMESTAMP,
    last_vuln_scan TIMESTAMP,
    last_exploit_scan TIMESTAMP,
    info_count INTEGER DEFAULT 0,
    vuln_count INTEGER DEFAULT 0,
    exploit_count INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scan_metadata_url ON scan_metadata(url);
```

## Migration Guide

### For New Projects

1. Install PostgreSQL
2. Create database: `CREATE DATABASE cybersecurity;`
3. Configure `.env` with connection details
4. Run: `python setup_database.py setup`
5. Use normally - agent auto-saves to database

### For Existing Projects (with CSV data)

1. Install PostgreSQL and dependencies
2. Setup database (steps 1-4 above)
3. Import existing CSV data:
   ```bash
   python import_csv_to_db.py --folder results --url https://your-target.com
   ```
4. Verify import: `python setup_database.py stats`
5. Old CSV files in `results/` can be kept as backup

## Key Features

### 1. Automatic Caching (3-day TTL)
```python
# Agent checks cache before running tools
if db.check_cache_valid(url, 'info', max_age_days=3):
    cached_data = db.get_info_records(url)
    # Use cached data
else:
    # Run new scan
```

### 2. Data Validation
All data validated with Pydantic before insertion:
- Type checking
- Timestamp parsing
- Default values
- CSV alias mapping

### 3. Performance Optimization
- Composite indexes on (url, timestamp)
- Connection pooling (10 base, 20 max)
- Query optimization with filters
- Batch operations

### 4. Metadata Tracking
`scan_metadata` table tracks:
- Last scan times for each tool
- Record counts
- Cache validation timestamps

### 5. Cleanup Operations
```python
# Delete records older than 30 days
db.clear_old_records(days=30)
```

## Usage Examples

### From Python
```python
from llm.database import DatabaseManager

db = DatabaseManager()

# Save results
info_data = read_csv_file('info.csv')
db.save_info_records('https://example.com', info_data)

# Get cached data (max 3 days old)
cached = db.get_info_records('https://example.com', max_age_days=3)

# Check cache validity
is_valid = db.check_cache_valid('https://example.com', 'info')

# Get metadata
metadata = db.get_scan_metadata('https://example.com')
```

### From Security Agent
```python
from llm.agent import SecurityAgent

# Agent automatically uses PostgreSQL
agent = SecurityAgent()

# Process message (auto-saves to DB)
result = await agent.process_user_message("Scan https://example.com")
```

### From Command Line
```bash
# Setup database
python setup_database.py setup

# Test connection
python setup_database.py test

# Show statistics
python setup_database.py stats

# Show scan info
python setup_database.py info --url https://example.com

# Cleanup old records
python setup_database.py cleanup --days 30

# Import CSV data
python import_csv_to_db.py --folder results --url https://example.com
```

## Environment Configuration

### Option 1: Full Connection String
```env
DATABASE_URL=postgresql://user:password@localhost:5432/cybersecurity
```

### Option 2: Individual Settings
```env
DB_USER=postgres
DB_PASSWORD=mypassword
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cybersecurity
```

## Benefits of PostgreSQL vs File-Based

| Feature | File-Based | PostgreSQL |
|---------|------------|------------|
| Concurrency | File locking issues | Multi-user safe |
| Performance | Slow for large datasets | Indexed queries |
| Queries | Load entire file | Filter/aggregate efficiently |
| Caching | Manual timestamp checks | Built-in metadata |
| Scalability | Limited | Scales well |
| Reliability | File corruption risk | ACID transactions |
| Backup | Manual file copies | pg_dump, replication |

## Next Steps

1. **Install PostgreSQL** if not already installed
2. **Run setup**: `python setup_database.py setup`
3. **Test connection**: `python setup_database.py test`
4. **Import existing data** (if any): `python import_csv_to_db.py --folder results --url <url>`
5. **Use agent normally** - it auto-saves to database

## Support

See `docs/DATABASE_SETUP.md` for detailed setup instructions and troubleshooting.
