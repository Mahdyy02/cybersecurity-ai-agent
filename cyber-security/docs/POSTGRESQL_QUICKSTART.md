# PostgreSQL Database Integration - Quick Reference

## Overview

The cybersecurity agent now uses **PostgreSQL** with **SQLAlchemy ORM** and **Pydantic validation** for data storage. All security assessment results are automatically saved to the database with 3-day caching.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

New packages: `sqlalchemy`, `psycopg2-binary`, `pydantic`

### 2. Setup PostgreSQL

**Windows:**
```cmd
setup_postgresql.bat
```

**Linux/Mac:**
```bash
chmod +x setup_postgresql.sh
./setup_postgresql.sh
```

**Manual Setup:**
1. Create database: `CREATE DATABASE cybersecurity;`
2. Configure `.env` with connection details
3. Run: `python setup_database.py setup`

### 3. Configure Connection

Create `.env` file (copy from `.env.example`):

```env
# Option 1: Full URL
DATABASE_URL=postgresql://postgres:password@localhost:5432/cybersecurity

# Option 2: Individual settings
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cybersecurity
```

## Database Tables

| Table | Description | CSV Schema |
|-------|-------------|------------|
| `info_records` | Information gathering (DNS, headers, ports) | `info.csv` |
| `vulnerability_records` | Vulnerability scan results | `vulns.csv` |
| `exploit_records` | Exploit validation results | `exploits.csv` |
| `scan_metadata` | Scan history and cache tracking | - |

## Usage

### Security Agent (Automatic)
```python
from llm.agent import SecurityAgent

# Agent automatically uses PostgreSQL
agent = SecurityAgent()

# All scans auto-save to database
result = await agent.process_user_message("Scan https://example.com")
```

### Direct Database Access
```python
from llm.database import DatabaseManager

db = DatabaseManager()

# Save data
info_data = read_csv_file('info.csv')
db.save_info_records('https://example.com', info_data)

# Get cached data (3 days max)
cached = db.get_info_records('https://example.com')

# Check cache validity
is_valid = db.check_cache_valid('https://example.com', 'info')
```

### Management Commands

```bash
# Test connection
python setup_database.py test

# Show statistics
python setup_database.py stats

# Show scan info for URL
python setup_database.py info --url https://example.com

# Cleanup old records (30+ days)
python setup_database.py cleanup --days 30

# Import existing CSV data
python import_csv_to_db.py --folder results --url https://example.com
```

## Caching Strategy

Automatic 3-day cache:
1. **Before scan:** Agent checks if cached data exists (<3 days old)
2. **If valid:** Uses cached data (faster, no new scan)
3. **If expired:** Runs new scan and updates database
4. **After scan:** Saves results with timestamp

Controlled by `scan_metadata` table.

## Key Features

✅ **Automatic caching** with 3-day TTL  
✅ **Data validation** using Pydantic schemas  
✅ **Indexed queries** for fast retrieval  
✅ **Transaction safety** with rollback  
✅ **Connection pooling** (10 base, 20 max)  
✅ **Multi-user support** (no file locking)  
✅ **Metadata tracking** (scan times, counts)  

## Migrating Existing CSV Data

If you have existing CSV files in `results/` folder:

```bash
# Import all CSV files for a URL
python import_csv_to_db.py --folder results --url https://your-target.com

# Import single file
python import_csv_to_db.py --file results/info.csv --type info --url https://example.com
```

## Troubleshooting

**Connection failed?**
- Check PostgreSQL is running: `pg_isready`
- Verify credentials in `.env`
- Ensure database exists: `CREATE DATABASE cybersecurity;`

**Import errors?**
- Check CSV file format matches expected schema
- Verify URL parameter is provided
- Check database has write permissions

**Performance issues?**
- Cleanup old records: `python setup_database.py cleanup --days 30`
- Check connection pool settings in `config/database_config.py`
- Verify indexes exist: `python setup_database.py setup`

## Documentation

📖 **Full guides:**
- [Database Setup Guide](docs/DATABASE_SETUP.md) - Complete installation and configuration
- [PostgreSQL Migration](docs/POSTGRESQL_MIGRATION.md) - Detailed migration guide

## File Structure

```
cyber-security/
├── llm/
│   ├── database.py          # PostgreSQL database manager
│   ├── agent.py             # Agent with PostgreSQL integration
│   └── ...
├── config/
│   └── database_config.py   # Database configuration
├── docs/
│   ├── DATABASE_SETUP.md    # Setup guide
│   └── POSTGRESQL_MIGRATION.md  # Migration details
├── setup_database.py        # Database CLI tool
├── import_csv_to_db.py      # CSV import tool
├── setup_postgresql.bat     # Windows setup script
├── setup_postgresql.sh      # Linux/Mac setup script
├── .env.example             # Configuration template
└── requirements.txt         # Updated with DB packages
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Full PostgreSQL connection string | - |
| `DB_USER` | Database username | postgres |
| `DB_PASSWORD` | Database password | postgres |
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_NAME` | Database name | cybersecurity |

## Security Best Practices

1. ✅ Don't commit `.env` file (in `.gitignore`)
2. ✅ Use strong passwords for PostgreSQL
3. ✅ Configure `pg_hba.conf` properly
4. ✅ Regular backups: `pg_dump -U postgres cybersecurity > backup.sql`
5. ✅ SSL in production: `?sslmode=require` in connection string

## Support

For issues or questions, refer to:
- [Database Setup Guide](docs/DATABASE_SETUP.md)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- Check PostgreSQL logs for connection issues
