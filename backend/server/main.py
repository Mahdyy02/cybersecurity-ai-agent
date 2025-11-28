"""
FastAPI Server - Main Application
API endpoints for Cybersecurity AI Agent
"""

import asyncio
import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.schemas import (
    ChatRequest,
    ChatResponse,
    SiteDetail,
    SiteListResponse,
    SiteHistoryResponse,
    DeleteResponse,
    ConversationMessage
)
from server.dependencies import get_security_agent, get_db_manager
from server.models import active_sessions, SiteSession
from llm.agent import SecurityAgent
from llm.database import DatabaseManager
from tools.utils import Logger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Cybersecurity AI Agent API",
    description="API for security testing with LLM-powered analysis",
    version="1.0.0"
)

# Configure CORS - Allow frontend to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "*"  # For development - restrict in production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Cybersecurity AI Agent API",
        "version": "1.0.0"
    }


@app.get("/api/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected"
    }


@app.post("/api/agent", response_model=ChatResponse)
async def chat_with_agent(
    request: ChatRequest,
    background_tasks: BackgroundTasks,
    agent: SecurityAgent = Depends(get_security_agent)
):
    """
    Main chat endpoint - Process user message and run security analysis
    
    Args:
        request: Chat request with prompt and optional current site
        agent: Security agent instance (injected)
    
    Returns:
        ChatResponse with detected site and agent reply
    """
    try:
        logger.info(f"Processing chat request: {request.prompt[:100]}...")
        
        # Extract or use current site
        url = None
        if request.currentSite:
            url = request.currentSite
        else:
            # Try to extract URL from prompt
            url = await agent.extract_url(request.prompt)
        
        # Process the message with the agent
        result = await agent.process_user_message(request.prompt)
        
        # Extract site information from result
        detected_url = result.get('url') or url
        response_text = result.get('response', 'Analysis completed.')
        process_steps = result.get('process_steps', [])
        
        # Normalize site URL if found
        if detected_url:
            if not detected_url.startswith(('http://', 'https://')):
                detected_url = 'https://' + detected_url
        
        # Create or update session in database
        session_id = None
        if detected_url:
            label = detected_url.replace('https://', '').replace('http://', '').rstrip('/')
            
            # Save to database
            db = get_db_manager()
            session_data = db.create_or_get_session(detected_url, label)
            session_id = session_data['id']
            
            # Save conversation messages
            db.save_conversation_message(session_id, "user", request.prompt)
            
            # Save process steps as a separate message (before main response)
            if process_steps:
                process_text = "\n".join(process_steps)
                db.save_conversation_message(session_id, "process", process_text)
            
            db.save_conversation_message(session_id, "assistant", response_text)
            
            # Also keep in active_sessions for backward compatibility
            if detected_url not in active_sessions:
                active_sessions[detected_url] = SiteSession(detected_url, label)
            
            session = active_sessions[detected_url]
            session.add_message("user", request.prompt)
            session.add_message("assistant", response_text)
        
        return ChatResponse(
            site=detected_url,
            reply=response_text,
            metadata={
                "timestamp": datetime.now().isoformat(),
                "process_steps": process_steps,
                "tools_executed": result.get('tools_executed', []),
                "execution_time": result.get('execution_time', 0)
            }
        )
    
    except Exception as e:
        logger.error(f"Error processing chat request: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error processing request: {str(e)}"
        )


@app.get("/api/sites", response_model=SiteListResponse)
async def get_sites(
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Get list of all analyzed sites
    
    Returns:
        List of sites with their details
    """
    try:
        # Get all sessions from database
        sessions = db.get_all_sessions()
        
        sites = []
        for session in sessions:
            # Get vulnerability and exploit counts
            vulns = db.get_session_results(session['id'], 'vulnerability')
            exploits = db.get_session_results(session['id'], 'exploit')
            
            label = session['url'].replace('https://', '').replace('http://', '').rstrip('/')
            
            site_detail = SiteDetail(
                id=session['id'],
                url=session['url'],
                label=label,
                created_at=session['created_at'],
                last_scan=session.get('last_activity'),
                vulnerability_count=len(vulns),
                exploit_count=len(exploits)
            )
            sites.append(site_detail)
        
        return SiteListResponse(sites=sites)
    
    except Exception as e:
        logger.error(f"Error fetching sites: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching sites: {str(e)}"
        )


@app.get("/api/sites/{site_id}", response_model=SiteDetail)
async def get_site(
    site_id: int,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Get details for a specific site
    
    Args:
        site_id: Site session ID
    
    Returns:
        Site details
    """
    try:
        session = db.get_site_session(site_id)
        if not session:
            raise HTTPException(status_code=404, detail="Site not found")
        
        vulns = db.get_session_results(site_id, 'vulnerability')
        exploits = db.get_session_results(site_id, 'exploit')
        
        label = session['url'].replace('https://', '').replace('http://', '').rstrip('/')
        
        return SiteDetail(
            id=session['id'],
            url=session['url'],
            label=label,
            created_at=session['created_at'],
            last_scan=session.get('last_activity'),
            vulnerability_count=len(vulns),
            exploit_count=len(exploits)
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching site {site_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching site: {str(e)}"
        )


@app.get("/api/sites/{site_id}/history", response_model=SiteHistoryResponse)
async def get_site_history(
    site_id: int,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Get conversation history and results for a site
    
    Args:
        site_id: Site session ID
    
    Returns:
        Site history with conversation, vulnerabilities, and exploits
    """
    try:
        session = db.get_site_session(site_id)
        if not session:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Get conversation history
        history = db.get_conversation_history(site_id)
        conversation = [
            ConversationMessage(
                role=msg['role'],
                content=msg['content'],
                timestamp=msg['timestamp']
            )
            for msg in history
        ]
        
        # Get vulnerabilities and exploits
        vulns = db.get_session_results(site_id, 'vulnerability')
        exploits = db.get_session_results(site_id, 'exploit')
        
        return SiteHistoryResponse(
            site_id=site_id,
            url=session['url'],
            conversation=conversation,
            vulnerabilities=vulns,
            exploits=exploits
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching history for site {site_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching history: {str(e)}"
        )


@app.delete("/api/sites/{site_id}", response_model=DeleteResponse)
async def delete_site(
    site_id: int,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Delete a site and all its associated data
    
    Args:
        site_id: Site session ID to delete
    
    Returns:
        Success message
    """
    try:
        session = db.get_site_session(site_id)
        if not session:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Delete from active sessions if present
        url = session['url']
        if url in active_sessions:
            del active_sessions[url]
        
        # Delete from database
        success = db.delete_session(site_id)
        
        if success:
            return DeleteResponse(
                success=True,
                message=f"Site {url} and all associated data deleted successfully"
            )
        else:
            raise HTTPException(
                status_code=500,
                detail="Failed to delete site from database"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting site {site_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error deleting site: {str(e)}"
        )


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("Starting Cybersecurity AI Agent API...")
    logger.info("Initializing database...")
    
    try:
        db = get_db_manager()
        db.create_tables()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
    
    logger.info("API Server ready!")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Cybersecurity AI Agent API...")


if __name__ == "__main__":
    import uvicorn
    
    # Run server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
