# PostgreSQL Troubleshooting Guide

## Common Issues and Solutions

### 1. Connection Failed: Password Authentication Failed

**Error:**
```
connection failed: FATAL: authentification par mot de passe échouée pour l'utilisateur « postgres »
```

**Solutions:**

#### Option A: Update .env with correct password
```env
DB_PASSWORD=your_actual_password
```

#### Option B: Reset PostgreSQL password

**Windows:**
1. Open pgAdmin or psql
2. Connect as postgres user
3. Run: `ALTER USER postgres WITH PASSWORD 'new_password';`

**Linux:**
```bash
sudo -u postgres psql
ALTER USER postgres WITH PASSWORD 'new_password';
\q
```

#### Option C: Check pg_hba.conf
Location:
- Windows: `C:\Program Files\PostgreSQL\15\data\pg_hba.conf`
- Linux: `/etc/postgresql/15/main/pg_hba.conf`

Change authentication method:
```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
```

Restart PostgreSQL after changes:
- Windows: Services → PostgreSQL → Restart
- Linux: `sudo systemctl restart postgresql`

---

### 2. Database Does Not Exist

**Error:**
```
database "cybersecurity" does not exist
```

**Solution:**

**Using psql:**
```bash
psql -U postgres
CREATE DATABASE cybersecurity;
\q
```

**Using SQL file:**
```bash
psql -U postgres -f database_setup.sql
```

**Using pgAdmin:**
1. Right-click "Databases"
2. Create → Database
3. Name: `cybersecurity`
4. Owner: `postgres`
5. Save

---

### 3. Duplicate Index Error

**Error:**
```
DuplicateTable: ERREUR: la relation « idx_url_timestamp » existe déjà
```

**Cause:** Tables/indexes already exist from previous setup

**Solution:**

The updated code now uses `checkfirst=True` which prevents this error. If you still see it:

**Option A: Re-run setup (safe)**
```bash
python setup_database.py setup
```

**Option B: Drop and recreate (careful - deletes all data!)**
```bash
psql -U postgres -d cybersecurity
DROP TABLE IF EXISTS info_records CASCADE;
DROP TABLE IF EXISTS vulnerability_records CASCADE;
DROP TABLE IF EXISTS exploit_records CASCADE;
DROP TABLE IF EXISTS scan_metadata CASCADE;
\q

python setup_database.py setup
```

---

### 4. Text SQL Expression Warning

**Error:**
```
Textual SQL expression 'SELECT 1' should be explicitly declared as text('SELECT 1')
```

**Status:** ✅ Fixed in latest version

If you still see this, update your code:
```python
from sqlalchemy import text
session.execute(text("SELECT 1"))  # Instead of session.execute("SELECT 1")
```

---

### 5. Connection Timeout / Too Many Connections

**Error:**
```
remaining connection slots are reserved
FATAL: sorry, too many clients already
```

**Solution:**

#### Check active connections:
```sql
psql -U postgres
SELECT count(*) FROM pg_stat_activity;
SELECT * FROM pg_stat_activity WHERE datname = 'cybersecurity';
```

#### Terminate idle connections:
```sql
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'cybersecurity' 
  AND state = 'idle'
  AND pid <> pg_backend_pid();
```

#### Increase max_connections in postgresql.conf:
```
max_connections = 100  # Increase from default 20
```

Restart PostgreSQL after changes.

---

### 6. Permission Denied

**Error:**
```
permission denied for database cybersecurity
permission denied to create table
```

**Solution:**

Grant proper permissions:
```sql
psql -U postgres
GRANT ALL PRIVILEGES ON DATABASE cybersecurity TO postgres;
\c cybersecurity
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
\q
```

---

### 7. PostgreSQL Not Running

**Error:**
```
could not connect to server
Is the server running?
```

**Check Status:**

**Windows:**
```cmd
sc query postgresql-x64-15
# or
services.msc  # Look for PostgreSQL
```

**Linux:**
```bash
sudo systemctl status postgresql
```

**Start Service:**

**Windows:**
```cmd
net start postgresql-x64-15
# or via Services GUI
```

**Linux:**
```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql  # Start on boot
```

---

### 8. Import CSV Data Failed

**Error when importing:**
```
Failed to save info: ...
Import failed: ...
```

**Solutions:**

#### Check CSV format matches schema:
- info.csv: Category, Key, Value, Timestamp
- vulns.csv: Type, Severity, URL, Parameter, Payload, Evidence, Description, Timestamp
- exploits.csv: Type, Status, URL, Parameter, Payload, Result, Data Extracted, Description, Timestamp

#### Check encoding:
```bash
# Convert to UTF-8 if needed
iconv -f ISO-8859-1 -t UTF-8 input.csv > output.csv
```

#### Check for special characters:
- Escape quotes in CSV
- Check for null bytes
- Verify timestamp format: ISO 8601 (2025-11-28T12:00:00)

---

## Diagnostic Commands

### Test Connection
```bash
python setup_database.py test
```

### Check Database Info
```bash
psql -U postgres -d cybersecurity
\dt                    # List tables
\d info_records        # Describe table structure
\di                    # List indexes
SELECT COUNT(*) FROM info_records;
SELECT COUNT(*) FROM vulnerability_records;
```

### View Connection Settings
```bash
psql -U postgres
SHOW all;
SHOW max_connections;
SHOW shared_buffers;
```

### Check Logs

**Windows:**
```
C:\Program Files\PostgreSQL\15\data\log\
```

**Linux:**
```bash
sudo tail -f /var/log/postgresql/postgresql-15-main.log
```

---

## Quick Fixes Checklist

Before asking for help, try:

1. ✅ Check PostgreSQL is running
2. ✅ Verify database exists: `psql -U postgres -l`
3. ✅ Test connection: `python setup_database.py test`
4. ✅ Check .env file has correct credentials
5. ✅ Verify user has permissions: `GRANT ALL PRIVILEGES...`
6. ✅ Check PostgreSQL logs for detailed errors
7. ✅ Restart PostgreSQL service
8. ✅ Try connecting with psql directly: `psql -U postgres -d cybersecurity`

---

## Reset Everything (Nuclear Option)

If nothing works and you want to start fresh:

```bash
# 1. Backup data (if any)
python setup_database.py stats  # Check what you have
pg_dump -U postgres cybersecurity > backup.sql  # Backup

# 2. Drop database
psql -U postgres
DROP DATABASE IF EXISTS cybersecurity;
CREATE DATABASE cybersecurity;
\q

# 3. Re-run setup
python setup_database.py setup

# 4. Import data (if you had any)
python import_csv_to_db.py --folder results --url https://your-url.com
```

---

## Still Having Issues?

1. **Check PostgreSQL version:** `psql --version` (Should be 12+)
2. **Check Python packages:** `pip list | grep -E "sqlalchemy|psycopg2|pydantic"`
3. **Test with psql directly:** `psql -U postgres -d cybersecurity -c "SELECT 1;"`
4. **Check firewall:** PostgreSQL uses port 5432
5. **Review logs:** Both PostgreSQL logs and Python stack traces

Include this information when reporting issues:
- PostgreSQL version
- Python version
- OS (Windows/Linux/Mac)
- Full error message
- Output of `python setup_database.py test`
