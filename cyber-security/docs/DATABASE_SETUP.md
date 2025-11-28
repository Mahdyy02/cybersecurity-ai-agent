# PostgreSQL Database Setup Guide

## Overview

This project uses PostgreSQL with SQLAlchemy ORM and Pydantic for data validation. All security assessment data (information gathering, vulnerabilities, exploits) is stored in PostgreSQL with automatic caching and 3-day TTL.

## Quick Start

### 1. Install PostgreSQL

**Windows:**
```cmd
# Download from https://www.postgresql.org/download/windows/
# Or use chocolatey:
choco install postgresql
```

**Linux:**
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib
```

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

### 2. Create Database

```bash
# Login to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE cybersecurity;

# Create user (optional)
CREATE USER cyberuser WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE cybersecurity TO cyberuser;

# Exit
\q
```

### 3. Configure Connection

Copy `.env.example` to `.env` and update credentials:

```bash
cp .env.example .env
```

Edit `.env`:
```env
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/cybersecurity
```

Or use individual settings:
```env
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cybersecurity
```

### 4. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `sqlalchemy==2.0.23` - ORM
- `psycopg2-binary==2.9.9` - PostgreSQL driver
- `pydantic==2.5.2` - Data validation

### 5. Initialize Database

```bash
python setup_database.py setup
```

This creates all required tables:
- `info_records` - Information gathering results
- `vulnerability_records` - Vulnerability scan results
- `exploit_records` - Exploit validation results
- `scan_metadata` - Scan timestamps and counts

## Database Schema

### info_records
Stores information gathering results (DNS, HTTP headers, ports, etc.)

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| url | String(2048) | Target URL |
| category | String(255) | Info category (DNS Records, HTTP Headers, etc.) |
| key | String(255) | Info key |
| value | Text | Info value |
| timestamp | DateTime | When info was gathered |

**Indexes:** `url`, `url+timestamp`, `category`

### vulnerability_records
Stores vulnerability scan results

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| url | String(2048) | Vulnerable URL |
| type | String(255) | Vulnerability type (SQL Injection, XSS, etc.) |
| severity | String(50) | Severity level (Low, Medium, High, Critical) |
| parameter | String(255) | Vulnerable parameter |
| payload | Text | Payload used |
| evidence | Text | Evidence of vulnerability |
| description | Text | Vulnerability description |
| timestamp | DateTime | When found |

**Indexes:** `url`, `url+timestamp`, `type+severity`

### exploit_records
Stores exploit validation results

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| url | String(2048) | Exploited URL |
| type | String(255) | Exploit type |
| status | String(100) | Status (Exploited, Failed, Not Exploited) |
| parameter | String(255) | Exploited parameter |
| payload | Text | Payload used |
| result | Text | Exploitation result |
| data_extracted | Text | Data extracted from exploitation |
| description | Text | Description |
| timestamp | DateTime | When validated |

**Indexes:** `url`, `url+timestamp`, `type+status`

### scan_metadata
Tracks scan history and counts

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| url | String(2048) | Target URL (unique) |
| last_info_scan | DateTime | Last info gathering timestamp |
| last_vuln_scan | DateTime | Last vulnerability scan timestamp |
| last_exploit_scan | DateTime | Last exploit validation timestamp |
| info_count | Integer | Number of info records |
| vuln_count | Integer | Number of vulnerabilities |
| exploit_count | Integer | Number of exploits |
| updated_at | DateTime | Last update timestamp |

**Indexes:** `url`

## Usage

### From Python Code

```python
from llm.database import DatabaseManager

# Initialize
db = DatabaseManager()
db.create_tables()

# Save info records
info_data = [
    {'Category': 'DNS Records', 'Key': 'A Record', 'Value': '1.2.3.4', 'Timestamp': '2025-11-28T12:00:00'}
]
db.save_info_records('https://example.com', info_data)

# Get cached info (max 3 days old)
cached = db.get_info_records('https://example.com', max_age_days=3)

# Check if cache is valid
is_valid = db.check_cache_valid('https://example.com', 'info', max_age_days=3)

# Get scan metadata
metadata = db.get_scan_metadata('https://example.com')
```

### From Security Agent

```python
from llm.agent import SecurityAgent

# Agent automatically uses PostgreSQL
agent = SecurityAgent()

# Process message (auto-saves to database)
result = await agent.process_user_message("Scan https://example.com")
```

### Management Commands

```bash
# Test database connection
python setup_database.py test

# Show statistics
python setup_database.py stats

# Show scan info for URL
python setup_database.py info --url https://example.com

# Cleanup old records (default: 30 days)
python setup_database.py cleanup --days 30
```

## Caching Strategy

The system automatically caches results for 3 days:

1. **Before scanning:** Agent checks if valid cached data exists
2. **If cache valid:** Uses cached data (saves time)
3. **If cache expired:** Runs new scan and updates database
4. **After scanning:** Saves results to database with timestamp

Cache validation uses `scan_metadata` table to track last scan times.

## Data Validation

All data is validated using Pydantic schemas before insertion:

```python
from llm.database import InfoRecordSchema, VulnerabilityRecordSchema, ExploitRecordSchema

# Validate info record
info = InfoRecordSchema(
    Category='DNS Records',
    Key='A Record', 
    Value='1.2.3.4'
)

# Validation automatically:
# - Parses timestamps
# - Sets defaults
# - Enforces types
# - Handles CSV column aliases
```

## Performance Optimization

### Indexes
- Composite indexes on `(url, timestamp)` for fast cache lookups
- Category/type indexes for filtering
- Connection pooling (10 connections, 20 max overflow)

### Query Tips
```python
# Fast: Uses index
db.get_info_records('https://example.com')

# Fast: Filtered by category
session.query(InfoRecord).filter(
    InfoRecord.category == 'DNS Records'
).all()

# Fast: Recent records only
db.get_vulnerability_records('https://example.com', max_age_days=1)
```

### Cleanup
Regularly cleanup old records:
```bash
# Delete records older than 30 days
python setup_database.py cleanup --days 30
```

## Troubleshooting

### Connection Issues

**Error:** `could not connect to server`
- Check PostgreSQL is running: `pg_isready`
- Verify credentials in `.env`
- Check firewall allows port 5432

**Error:** `database "cybersecurity" does not exist`
```sql
psql -U postgres
CREATE DATABASE cybersecurity;
```

**Error:** `password authentication failed`
- Update password in `.env`
- Check PostgreSQL pg_hba.conf settings

### Import CSV Data

If you have existing CSV files in `results/` folder:

```python
from llm.database import DatabaseManager
from tools.utils import read_csv_file

db = DatabaseManager()

# Import info.csv
info_data = read_csv_file('results/info.csv')
db.save_info_records('https://example.com', info_data)

# Import vulns.csv
vuln_data = read_csv_file('results/vulns.csv')
db.save_vulnerability_records('https://example.com', vuln_data)

# Import exploits.csv
exploit_data = read_csv_file('results/exploits.csv')
db.save_exploit_records('https://example.com', exploit_data)
```

### View Data Directly

```bash
psql -U postgres -d cybersecurity

# Show all tables
\dt

# Count records
SELECT COUNT(*) FROM info_records;
SELECT COUNT(*) FROM vulnerability_records;
SELECT COUNT(*) FROM exploit_records;

# Recent scans
SELECT url, last_info_scan, vuln_count FROM scan_metadata;

# Vulnerabilities by severity
SELECT severity, COUNT(*) FROM vulnerability_records GROUP BY severity;
```

## Migration from File-Based Storage

The system has been migrated from file-based JSON storage to PostgreSQL:

| Old System | New System |
|------------|------------|
| `database/{url}_info.json` | `info_records` table |
| `database/{url}_vulns.json` | `vulnerability_records` table |
| `database/{url}_exploits.json` | `exploit_records` table |
| File timestamps | `scan_metadata` table |

All tool outputs now save directly to PostgreSQL while maintaining CSV compatibility.

## Security Best Practices

1. **Don't commit .env** - Already in `.gitignore`
2. **Use strong passwords** - For PostgreSQL user
3. **Limit access** - Configure pg_hba.conf properly
4. **Regular backups:**
   ```bash
   pg_dump -U postgres cybersecurity > backup.sql
   ```
5. **SSL connections** (production):
   ```env
   DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require
   ```

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Full PostgreSQL connection string | - |
| `DB_USER` | Database username | postgres |
| `DB_PASSWORD` | Database password | postgres |
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_NAME` | Database name | cybersecurity |
| `CACHE_MAX_AGE_DAYS` | Cache TTL in days | 3 |

## Support

For issues:
1. Check PostgreSQL logs: `tail -f /var/log/postgresql/postgresql-*.log`
2. Test connection: `python setup_database.py test`
3. Verify credentials in `.env`
4. Check database exists: `psql -U postgres -l`
