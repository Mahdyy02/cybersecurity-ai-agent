# Cybersecurity AI Agent

An intelligent AI-powered cybersecurity assessment platform that automates website vulnerability scanning, information gathering, and exploit validation. The agent uses natural language processing to understand security queries and orchestrates comprehensive security testing workflows.

![AI Agent Demo](ai_agent.png)

## Features

### Intelligent Agent
- **Natural Language Interface**: Interact with the agent using conversational queries
- **Intent Recognition**: Automatically understands what type of security assessment you need
- **Conversation Memory**: Maintains context across multiple queries in the same session
- **Smart Severity Filtering**: Automatically focuses on high and medium severity vulnerabilities

### Security Assessment Tools
1. **Information Gatherer**
   - Server fingerprinting
   - Technology stack detection
   - SSL/TLS certificate analysis
   - DNS and WHOIS information
   - HTTP headers analysis

2. **Vulnerability Scanner**
   - SQL Injection detection (error-based and blind)
   - Cross-Site Scripting (XSS) detection
   - Cross-Site Request Forgery (CSRF) detection
   - Security misconfiguration identification
   - Information disclosure vulnerabilities
   - Directory listing detection
   - Sensitive file exposure

3. **Exploit Validator**
   - Automated SQL injection exploitation (limited to 5 per type)
   - XSS payload validation
   - CSRF proof-of-concept generation
   - Real-world attack simulation

### Database Integration
- PostgreSQL backend for persistent storage
- Automatic caching (3-day default retention)
- Conversation history tracking
- Site session management
- Scheduled cleanup of old records

### Smart Automation
- Auto-scan when no recent data exists
- Duplicate form/URL detection to avoid redundant testing
- Timeout controls for vulnerability testing (300s default)
- Early stopping after finding first vulnerability per parameter

## Getting Started

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- Modern web browser

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Mahdyy02/cybersecurity-ai-agent.git
cd cybersecurity-ai-agent
```

2. **Install Python dependencies**
```bash
cd backend
pip install -r requirements.txt
```

3. **Set up PostgreSQL database**
```bash
# Create database
createdb cybersecurity

# Run the setup script (creates tables and indexes)
python -c "from llm.database import DatabaseManager; db = DatabaseManager(); db.create_tables()"
```

4. **Configure environment variables**

Create a `.env` file in the `backend` directory:

```env
# LLM API Configuration
OPENROUTER_API_KEY="your-openrouter-api-key-here"

# Database Configuration
DATABASE_URL=postgresql://postgres:your_password@127.0.0.1:5432/cybersecurity

DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=cybersecurity

# Cache Settings
CACHE_MAX_AGE_DAYS=3
CLEANUP_OLD_RECORDS_DAYS=30

# Vulnerability Testing Settings
VULN_TEST_TIMEOUT=300
```

**Getting an OpenRouter API Key:**
- Sign up at [OpenRouter](https://openrouter.ai/)
- Navigate to API Keys section
- Create a new API key
- Copy and paste it into your `.env` file

5. **Start the backend server**
```bash
cd backend
python -m uvicorn server.main:app --reload --host 0.0.0.0 --port 8000
```

6. **Open the web interface**
```bash
# Open in your browser
open app.html
# or simply double-click app.html
```

## Usage Examples

### Basic Queries
```
"Scan http://testphp.vulnweb.com for vulnerabilities"
"What are the high severity vulnerabilities for this website?"
"Check if the site is SQL injectable"
"Show me all XSS vulnerabilities"
```

### Information Gathering
```
"Gather information about http://example.com"
"What technology stack does this site use?"
"Show me the server details"
```

### Follow-up Questions
```
User: "Scan http://testphp.vulnweb.com"
Agent: [Performs scan and shows results]

User: "Show me only the critical vulnerabilities"
Agent: [Filters to high severity - remembers the URL from context]

User: "Can you validate these exploits?"
Agent: [Runs exploit validator on the same site]
```

## Architecture

```
cybersecurity-ai-agent/
├── backend/
│   ├── llm/
│   │   ├── agent.py           # Main AI orchestrator
│   │   ├── database.py        # PostgreSQL integration
│   │   ├── generate.py        # LLM response generation
│   │   └── prompts.py         # System prompts
│   ├── tools/
│   │   ├── info_gatherer.py   # Information gathering tool
│   │   ├── vulnerability_scanner.py  # Vulnerability detection
│   │   └── exploit_validator.py      # Exploit validation
│   ├── server/
│   │   ├── main.py            # FastAPI application
│   │   ├── schemas.py         # Pydantic models
│   │   └── dependencies.py    # Dependency injection
│   └── config/
│       └── database_config.py # Database configuration
├── frontend/
│   ├── app.html               # Main web interface
│   ├── script.js              # Frontend logic
│   └── styles.css             # Styling
└── ai_agent.png              # Demo screenshot
```

## Configuration

### Timeout Settings
Adjust vulnerability testing timeout in `.env`:
```env
VULN_TEST_TIMEOUT=300  # 5 minutes (300 seconds)
```

### Cache Settings
Control how long scan results are cached:
```env
CACHE_MAX_AGE_DAYS=3          # Use cached results for 3 days
CLEANUP_OLD_RECORDS_DAYS=30   # Delete records older than 30 days
```

### Database Connection
Customize PostgreSQL connection:
```env
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=cybersecurity
DB_USER=postgres
DB_PASSWORD=your_password
```

## API Endpoints

### Chat with Agent
```http
POST /chat
Content-Type: application/json

{
  "prompt": "Scan http://example.com for vulnerabilities",
  "sessionId": 1  // Optional: for conversation context
}
```

### List All Sites
```http
GET /sites
```

### Get Site History
```http
GET /sites/{site_id}/history
```

### Delete Site
```http
DELETE /sites/{site_id}
```

## Testing

Test the vulnerability scanner directly:
```bash
cd backend/tools
python vulnerability_scanner.py -u http://testphp.vulnweb.com -o results.csv
```

Test the exploit validator:
```bash
python exploit_validator.py -u http://testphp.vulnweb.com -i vulnerabilities.csv -o exploits.csv
```

## Security Considerations

**Important:** This tool is designed for **authorized security testing only**. 

- Only test websites you own or have explicit permission to test
- Running vulnerability scans against unauthorized targets is illegal
- The exploit validator performs real attacks - use responsibly
- Consider rate limiting when scanning production systems

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with FastAPI, PostgreSQL, and OpenRouter AI
- Inspired by professional security tools like Acunetix and Burp Suite
- Special thanks to the cybersecurity community

## Contact

For questions or support, please open an issue on GitHub.

---

**Disclaimer:** This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
