"""
Start FastAPI Server
Quick launcher for the cybersecurity API server
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("Starting Cybersecurity AI Agent API Server")
    print("=" * 60)
    print()
    print("API Documentation will be available at:")
    print("  • Swagger UI: http://localhost:8000/docs")
    print("  • ReDoc:      http://localhost:8000/redoc")
    print()
    print("Frontend should connect to: http://localhost:8000")
    print()
    print("Press CTRL+C to stop the server")
    print("=" * 60)
    print()
    
    # Start the server
    uvicorn.run(
        "server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )
