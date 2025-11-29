"""
LLM Agent Orchestrator
Coordinates between LLM decisions and security tools execution
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm.generate import generate_chatbot_response
from llm.prompts import (
    URL_EXTRACTOR_PROMPT,
    INTENT_ANALYZER_PROMPT,
    RESULT_SUMMARIZER_PROMPT,
    CONVERSATION_AGENT_PROMPT
)
from llm.database import DatabaseManager
from tools.info_gatherer import InfoGatherer
from tools.vulnerability_scanner import VulnerabilityScanner
from tools.exploit_validator import ExploitValidator
from tools.utils import read_csv_file, Logger


class SecurityAgent:
    """
    Main AI Agent that orchestrates security assessments
    """
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize security agent
        
        Args:
            database_url: PostgreSQL connection string. If None, uses DATABASE_URL env var
        """
        self.db = DatabaseManager(database_url)
        self.db.create_tables()  # Ensure tables exist
        self.current_url = None
        self.temp_files = {}  # Store temporary file paths
    
    async def extract_url(self, user_message: str) -> Optional[str]:
        """Extract URL from user message using LLM"""
        Logger.info("Extracting URL from user message...")
        
        try:
            response = await generate_chatbot_response(
                system_prompt=URL_EXTRACTOR_PROMPT,
                user_message=user_message,
                temperature=0.1,
                max_tokens=100
            )
            
            # Check if response is empty or error
            if not response or response.startswith("Error"):
                Logger.warning("LLM did not return a valid URL response")
                return None
            
            url = response.strip()
            
            if url == "NO_URL_FOUND" or not url:
                return None
            
            # Check if the response is actually an error message
            if "Error" in url or "error" in url.lower():
                Logger.warning(f"LLM returned error: {url}")
                return None
            
            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Basic validation
            parsed = urlparse(url)
            if parsed.netloc:
                Logger.success(f"Extracted URL: {url}")
                return url
            
            return None
            
        except Exception as e:
            Logger.error(f"URL extraction error: {str(e)}")
            return None
    
    async def analyze_intent(self, user_message: str, url: Optional[str]) -> Dict:
        """Analyze user intent and create execution plan"""
        Logger.info("Analyzing user intent...")
        
        try:
            # Prepare context for LLM
            context = f"URL: {url}" if url else "No URL provided"
            
            response = await generate_chatbot_response(
                system_prompt=INTENT_ANALYZER_PROMPT,
                user_message=user_message,
                temperature=0.3,
                max_tokens=500,
                context=context
            )
            
            # Check if response is empty or error
            if not response or response.startswith("Error"):
                Logger.warning("LLM did not return a valid intent response, using default plan")
                # Return default vulnerability scan plan
                return {
                    "intent": "vulnerability_scan",
                    "url": url,
                    "check_database": False,
                    "actions": [
                        {"action": "info_gathering", "params": {}},
                        {"action": "vulnerability_scan", "params": {}}
                    ],
                    "needs_user_confirmation": False,
                    "display_to_user": "Performing security analysis..."
                }
            
            # Parse JSON response
            # Clean response (remove markdown code blocks if present)
            response = response.strip()
            if response.startswith('```'):
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]
            
            plan = json.loads(response)
            Logger.success(f"Intent: {plan.get('intent', 'unknown')}")
            
            return plan
            
        except json.JSONDecodeError as e:
            Logger.error(f"Failed to parse intent JSON: {str(e)}")
            Logger.info(f"Response was: {response[:200]}")
            # Return default vulnerability scan plan
            return {
                "intent": "vulnerability_scan",
                "url": url,
                "check_database": False,
                "actions": [
                    {"action": "info_gathering", "params": {}},
                    {"action": "vulnerability_scan", "params": {}}
                ],
                "needs_user_confirmation": False,
                "display_to_user": "Performing security analysis..."
            }
        except Exception as e:
            Logger.error(f"Intent analysis error: {str(e)}")
            # Return default vulnerability scan plan
            return {
                "intent": "vulnerability_scan",
                "url": url,
                "check_database": False,
                "actions": [
                    {"action": "info_gathering", "params": {}},
                    {"action": "vulnerability_scan", "params": {}}
                ],
                "needs_user_confirmation": False,
                "display_to_user": "Performing security analysis..."
            }
    
    async def execute_action(self, action: Dict, url: str) -> Dict:
        """Execute a single action and return results"""
        action_name = action.get('action')
        params = action.get('params', {})
        
        Logger.banner(f"Executing: {action_name}")
        
        result = {
            'action': action_name,
            'status': 'pending',
            'data': None,
            'message': ''
        }
        
        try:
            if action_name == 'query_database':
                severity_filter = params.get('severity_filter')
                result = await self._query_database(url, params.get('query_type', 'all'), severity_filter)
            
            elif action_name == 'info_gathering':
                result = await self._run_info_gathering(url)
            
            elif action_name == 'vulnerability_scan':
                result = await self._run_vulnerability_scan(url)
            
            elif action_name == 'exploit_validation':
                demo_mode = params.get('demo_mode', False)
                result = await self._run_exploit_validation(url, demo_mode)
            
            elif action_name == 'display_info':
                result = await self._display_info(url)
            
            elif action_name == 'display_vulnerabilities':
                result = await self._display_vulnerabilities(url)
            
            else:
                result['status'] = 'error'
                result['message'] = f"Unknown action: {action_name}"
        
        except Exception as e:
            result['status'] = 'error'
            result['message'] = str(e)
            Logger.error(f"Action execution error: {str(e)}")
        
        return result
    
    async def _run_info_gathering(self, url: str) -> Dict:
        """Run information gathering tool"""
        try:
            # Create temp file path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join("temp", f"info_{timestamp}.csv")
            os.makedirs("temp", exist_ok=True)
            
            # Run tool
            gatherer = InfoGatherer(url, output_file)
            success = gatherer.run()
            
            if success:
                # Read results
                data = read_csv_file(output_file)
                
                # Save to PostgreSQL database (consolidated format - one row per website)
                stats = self.db.save_website_info(url, data)
                Logger.success(f"Saved website info to database: {stats['saved_records']} records " +
                              f"({stats['filtered_records']} noisy records filtered)")
                
                return {
                    'action': 'info_gathering',
                    'status': 'success',
                    'data': data,
                    'message': f"Collected {stats['saved_records']} information entries (filtered {stats['filtered_records']} noisy records)",
                    'stats': stats
                }
            else:
                return {
                    'action': 'info_gathering',
                    'status': 'failed',
                    'data': None,
                    'message': 'Information gathering failed'
                }
        
        except Exception as e:
            return {
                'action': 'info_gathering',
                'status': 'error',
                'data': None,
                'message': str(e)
            }
    
    async def _run_vulnerability_scan(self, url: str) -> Dict:
        """Run vulnerability scanner"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join("temp", f"vulns_{timestamp}.csv")
            os.makedirs("temp", exist_ok=True)
            
            scanner = VulnerabilityScanner(url, output_file)
            success = scanner.run()
            
            if success:
                data = read_csv_file(output_file)
                
                # Save to PostgreSQL database
                count = self.db.save_vulnerability_records(url, data)
                Logger.success(f"Saved {count} vulnerability records to database")
                
                self.temp_files['vulnerabilities'] = output_file
                
                return {
                    'action': 'vulnerability_scan',
                    'status': 'success',
                    'data': data,
                    'message': f'Found {len(data)} potential issues'
                }
            else:
                return {
                    'action': 'vulnerability_scan',
                    'status': 'failed',
                    'data': None,
                    'message': 'Vulnerability scan failed'
                }
        
        except Exception as e:
            return {
                'action': 'vulnerability_scan',
                'status': 'error',
                'data': None,
                'message': str(e)
            }
    
    async def _run_exploit_validation(self, url: str, demo_mode: bool = False) -> Dict:
        """Run exploit validation"""
        try:
            # Get vulnerabilities file
            vulns_file = self.temp_files.get('vulnerabilities')
            if not vulns_file or not os.path.exists(vulns_file):
                # Try to get from PostgreSQL database
                db_vulns = self.db.get_vulnerability_records(url)
                if not db_vulns:
                    return {
                        'action': 'exploit_validation',
                        'status': 'error',
                        'data': None,
                        'message': 'No vulnerabilities found. Run vulnerability scan first.'
                    }
                
                # Create temp file from DB data
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                vulns_file = os.path.join("temp", f"vulns_{timestamp}.csv")
                os.makedirs("temp", exist_ok=True)
                
                # Write DB data to CSV
                import csv
                with open(vulns_file, 'w', newline='', encoding='utf-8') as f:
                    if db_vulns:
                        writer = csv.DictWriter(f, fieldnames=db_vulns[0].keys())
                        writer.writeheader()
                        writer.writerows(db_vulns)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join("temp", f"exploits_{timestamp}.csv")
            
            validator = ExploitValidator(url, vulns_file, output_file, demo_mode=demo_mode)
            success = validator.run()
            
            if success:
                data = read_csv_file(output_file)
                
                # Save to PostgreSQL database
                count = self.db.save_exploit_records(url, data)
                Logger.success(f"Saved {count} exploit records to database")
                
                return {
                    'action': 'exploit_validation',
                    'status': 'success',
                    'data': data,
                    'message': f'Validated {len(data)} vulnerabilities'
                }
            else:
                return {
                    'action': 'exploit_validation',
                    'status': 'failed',
                    'data': None,
                    'message': 'Exploit validation failed'
                }
        
        except Exception as e:
            return {
                'action': 'exploit_validation',
                'status': 'error',
                'data': None,
                'message': str(e)
            }
    
    async def _query_database(self, url: str, query_type: str = 'all', severity_filter: Optional[List[str]] = None) -> Dict:
        """
        Query database for existing information
        
        Args:
            url: Target URL
            query_type: Type of data to query ('all', 'vulnerabilities', 'info', 'ports')
            severity_filter: List of severity levels for vulnerabilities (e.g., ['High', 'Medium'])
        """
        Logger.info(f"Querying database for: {query_type}")
        
        results = {
            'action': 'query_database',
            'status': 'success',
            'data': {},
            'message': '',
            'needs_scan': False
        }
        
        try:
            # Get website info
            if query_type in ['all', 'info', 'ports']:
                try:
                    website_info = self.db.get_website_info(url)
                    if website_info:
                        results['data']['website_info'] = website_info
                        Logger.success(f"Found website info for {url}")
                    else:
                        # Fallback to old format
                        db_info = self.db.get_info_records(url)
                        if db_info:
                            results['data']['info_records'] = db_info
                            Logger.success(f"Found {len(db_info)} info records for {url}")
                except Exception as e:
                    Logger.error(f"Error fetching website info: {str(e)}")
                    import traceback
                    traceback.print_exc()
            
            # Get vulnerabilities with optional severity filtering
            if query_type in ['all', 'vulnerabilities', 'vulns']:
                try:
                    db_vulns = self.db.get_vulnerability_records(url, severity_filter=severity_filter)
                    if db_vulns:
                        results['data']['vulnerabilities'] = db_vulns
                        if severity_filter:
                            Logger.success(f"Found {len(db_vulns)} vulnerabilities (severity: {', '.join(severity_filter)}) for {url}")
                        else:
                            Logger.success(f"Found {len(db_vulns)} vulnerabilities for {url}")
                except Exception as e:
                    Logger.error(f"Error fetching vulnerabilities: {str(e)}")
                    import traceback
                    traceback.print_exc()
            
            # Check if we found any data
            if not results['data']:
                results['status'] = 'not_found'
                results['needs_scan'] = True
                results['message'] = f"No data found for {url}. Initiating scan..."
            else:
                # Check if vulnerabilities query returned no results
                if query_type in ['vulnerabilities', 'vulns', 'all']:
                    if 'vulnerabilities' not in results['data'] or len(results['data']['vulnerabilities']) == 0:
                        results['needs_scan'] = True
                        if severity_filter:
                            results['message'] = f"No {', '.join(severity_filter).lower()} severity vulnerabilities found. Performing scan..."
                        else:
                            results['message'] = f"No vulnerabilities found. Performing scan..."
                    else:
                        # Count findings
                        vuln_count = len(results['data'].get('vulnerabilities', []))
                        info_available = 'website_info' in results['data'] or 'info_records' in results['data']
                        
                        parts = []
                        if info_available:
                            parts.append("website information")
                        if vuln_count > 0:
                            if severity_filter:
                                parts.append(f"{vuln_count} {', '.join(severity_filter).lower()} severity vulnerabilities")
                            else:
                                parts.append(f"{vuln_count} vulnerabilities")
                        
                        results['message'] = f"Found {' and '.join(parts)} in database"
                else:
                    # For non-vulnerability queries
                    info_available = 'website_info' in results['data'] or 'info_records' in results['data']
                    if info_available:
                        results['message'] = "Found website information in database"
                    else:
                        results['needs_scan'] = True
                        results['message'] = "No information found. Performing scan..."
            
            return results
            
        except Exception as e:
            Logger.error(f"Database query error: {str(e)}")
            return {
                'action': 'query_database',
                'status': 'error',
                'data': None,
                'message': f"Error querying database: {str(e)}",
                'needs_scan': False
            }
    
    async def _display_info(self, url: str) -> Dict:
        """Display cached information (using consolidated website info)"""
        # Try new consolidated format first
        website_info = self.db.get_website_info(url)
        
        if website_info:
            return {
                'action': 'display_info',
                'status': 'success',
                'data': website_info,
                'message': f"Website info from {website_info['last_updated']} (scan #{website_info['scan_count']})"
            }
        
        # Fallback to old format for backward compatibility
        db_info = self.db.get_info_records(url)
        
        if db_info:
            # Get metadata for timestamp
            metadata = self.db.get_scan_metadata(url)
            timestamp = metadata.get('last_info_scan') if metadata else 'unknown'
            
            return {
                'action': 'display_info',
                'status': 'success',
                'data': db_info,
                'message': f"Information from {timestamp} (legacy format)"
            }
        else:
            return {
                'action': 'display_info',
                'status': 'not_found',
                'data': None,
                'message': 'No cached information found. Run info gathering first.'
            }
    
    async def _display_vulnerabilities(self, url: str) -> Dict:
        """Display cached vulnerabilities"""
        db_vulns = self.db.get_vulnerability_records(url)
        
        if db_vulns:
            # Get metadata for timestamp
            metadata = self.db.get_scan_metadata(url)
            timestamp = metadata.get('last_vuln_scan') if metadata else 'unknown'
            
            return {
                'action': 'display_vulnerabilities',
                'status': 'success',
                'data': db_vulns,
                'message': f"Vulnerabilities from {timestamp}"
            }
        else:
            return {
                'action': 'display_vulnerabilities',
                'status': 'not_found',
                'data': None,
                'message': 'No vulnerabilities found. Run scan first.'
            }
    
    async def summarize_results(self, results: List[Dict]) -> str:
        """Summarize results using LLM with ACTUAL data"""
        Logger.info("Generating summary...")
        
        try:
            # Prepare detailed data for summarization with ACTUAL findings
            detailed_data = []
            
            for result in results:
                action = result.get('action', 'unknown')
                status = result.get('status', 'unknown')
                data = result.get('data', [])
                
                if action == 'query_database' and status == 'success':
                    # Extract actual data from database query
                    if isinstance(data, dict):
                        # Vulnerabilities
                        if 'vulnerabilities' in data:
                            for vuln in data['vulnerabilities'][:10]:  # Limit to 10 for token size
                                detailed_data.append({
                                    'type': 'vulnerability',
                                    'name': vuln.get('Type', vuln.get('type', 'Unknown')),
                                    'location': vuln.get('URL', vuln.get('url', 'Unknown')),
                                    'severity': vuln.get('Severity', vuln.get('severity', 'Unknown')),
                                    'details': vuln.get('Description', vuln.get('details', vuln.get('Evidence', 'No details'))),
                                    'parameter': vuln.get('Parameter', 'N/A'),
                                    'payload': vuln.get('Payload', 'N/A'),
                                    'recommendation': vuln.get('Recommendation', vuln.get('recommendation', 'No recommendation'))
                                })
                        
                        # Website info
                        if 'website_info' in data:
                            info = data['website_info']
                            detailed_data.append({
                                'type': 'website_info',
                                'data': info
                            })
                        elif 'info_records' in data:
                            detailed_data.append({
                                'type': 'info_records',
                                'count': len(data['info_records']),
                                'sample': data['info_records'][:5]
                            })
                
                elif action == 'info_gathering' and data:
                    detailed_data.append({
                        'type': 'info_gathering_results',
                        'count': len(data),
                        'sample': data[:5]
                    })
                
                elif action == 'vulnerability_scan' and data:
                    for vuln in data[:10]:  # Limit to 10
                        detailed_data.append({
                            'type': 'vulnerability',
                            'name': vuln.get('Type', vuln.get('type', 'Unknown')),
                            'location': vuln.get('URL', vuln.get('url', 'Unknown')),
                            'severity': vuln.get('Severity', vuln.get('severity', 'Unknown')),
                            'details': vuln.get('Details', vuln.get('details', 'No details')),
                            'recommendation': vuln.get('Recommendation', vuln.get('recommendation', 'No recommendation'))
                        })
                
                elif action == 'exploit_validation' and data:
                    for exploit in data[:5]:
                        detailed_data.append({
                            'type': 'exploit_result',
                            'vulnerability': exploit.get('Type', 'Unknown'),
                            'success': exploit.get('Status', 'Unknown'),
                            'details': exploit.get('Details', 'No details')
                        })
            
            # If no data found, return simple message
            if not detailed_data:
                if any(r.get('status') == 'not_found' for r in results):
                    return "No data found in the database for this website. Would you like me to perform a security scan?"
                return "No significant findings to report."
            
            # Convert to JSON string for LLM
            data_json = json.dumps(detailed_data, indent=2)
            
            # Call LLM with ACTUAL data
            response = await generate_chatbot_response(
                system_prompt=RESULT_SUMMARIZER_PROMPT,
                user_message=f"ACTUAL SECURITY SCAN DATA (JSON format):\n\n{data_json}",
                temperature=0.4,
                max_tokens=1000
            )
            
            if response and response != "None" and not response.startswith("Error"):
                return response
            else:
                # Fallback: Create a simple summary from the data
                return self._create_fallback_summary(detailed_data)
        
        except Exception as e:
            Logger.error(f"Summarization error: {str(e)}")
            return self._create_fallback_summary(detailed_data if 'detailed_data' in locals() else [])
    
    def _create_fallback_summary(self, data: List[Dict]) -> str:
        """Create a basic summary when LLM fails"""
        if not data:
            return "Operations completed. No significant findings."
        
        vulns = [d for d in data if d.get('type') == 'vulnerability']
        exploits = [d for d in data if d.get('type') == 'exploit_result']
        
        summary = "🔍 Security Assessment Results\n\n"
        
        if vulns:
            # Count by severity
            severity_count = {}
            for v in vulns:
                sev = v.get('severity', 'Unknown')
                severity_count[sev] = severity_count.get(sev, 0) + 1
            
            summary += f"**Found {len(vulns)} vulnerabilities:**\n"
            for sev, count in severity_count.items():
                summary += f"  - {sev}: {count}\n"
            summary += "\n**Top Issues:**\n"
            for i, v in enumerate(vulns[:5], 1):
                param = v.get('parameter', 'N/A')
                summary += f"{i}. **{v.get('name')}** ({v.get('severity')})\n"
                summary += f"   📍 Location: {v.get('location')}\n"
                if param and param != 'N/A':
                    summary += f"   🎯 Parameter: {param}\n"
                summary += "\n"
        
        if exploits:
            summary += f"\n✅ {len(exploits)} vulnerabilities validated through exploitation\n"
        
        if not vulns and not exploits:
            summary = "✅ No significant vulnerabilities detected."
        
        return summary
    
    async def process_user_message(self, user_message: str, conversation_history: Optional[List[Dict]] = None) -> Dict:
        """
        Main entry point: Process user message and execute plan
        
        Args:
            user_message: Current user message
            conversation_history: Previous messages in conversation [{"role": "user/assistant", "content": "..."}]
        
        Returns:
            execution results and response for user
        """
        Logger.banner("Processing User Message")
        
        # Track process steps for frontend display
        process_steps = []
        
        # Build context from conversation history
        context_info = ""
        if conversation_history and len(conversation_history) > 0:
            context_info = "\n\nPREVIOUS CONVERSATION:\n"
            for msg in conversation_history[-6:]:  # Last 6 messages for context
                role = "User" if msg["role"] == "user" else "Assistant"
                context_info += f"{role}: {msg['content'][:200]}...\n"  # Truncate long messages
            Logger.info(f"Using conversation history with {len(conversation_history)} messages")
        
        # Step 1: Extract URL (check history first if no URL in current message)
        process_steps.append("🔍 Extracting URL from message...")
        url = await self.extract_url(user_message)
        
        # If no URL found in current message, check conversation history
        if not url and conversation_history:
            for msg in reversed(conversation_history):
                if msg["role"] == "user":
                    url = await self.extract_url(msg["content"])
                    if url:
                        Logger.info(f"Found URL in conversation history: {url}")
                        break
        
        if url:
            self.current_url = url
            process_steps.append(f"✓ URL detected: {url}")
        elif self.current_url:
            url = self.current_url
            process_steps.append(f"✓ Using current URL: {url}")
        else:
            process_steps.append("⚠ No URL found")
        
        # Step 2: Analyze intent and create plan (with conversation context)
        process_steps.append("🤖 Analyzing intent and creating execution plan...")
        
        # Enhance user message with context for intent analysis
        enhanced_message = user_message
        if context_info:
            enhanced_message = f"{context_info}\n\nCURRENT USER MESSAGE:\n{user_message}"
        
        plan = await self.analyze_intent(enhanced_message, url)
        if plan.get('actions'):
            process_steps.append(f"✓ Plan created: {len(plan['actions'])} action(s) to execute")
        
        # Step 3: Check if immediate response needed
        if plan.get('display_to_user') and not plan.get('actions'):
            return {
                'status': 'completed',
                'plan': plan,
                'results': [],
                'response': plan['display_to_user'],
                'process_steps': process_steps
            }
        
        # Step 4: Execute actions
        results = []
        auto_scan_triggered = False
        
        for action in plan.get('actions', []):
            action_name = action.get('action', 'unknown')
            process_steps.append(f"⚙️ Executing: {action_name}...")
            
            if not url and action_name != 'query_database':
                results.append({
                    'action': action.get('action'),
                    'status': 'error',
                    'message': 'No URL provided'
                })
                continue
            
            # Special handling for query_database action
            if action_name == 'query_database':
                query_type = plan.get('query_type', 'all')
                severity_filter = plan.get('severity_filter')
                action['params'] = action.get('params', {})
                action['params']['query_type'] = query_type
                if severity_filter:
                    action['params']['severity_filter'] = severity_filter
            
            # Check database if needed (for scan actions)
            if plan.get('check_database') and action_name != 'query_database':
                if action['action'] == 'info_gathering':
                    # Check if cache is valid (less than 3 days old)
                    if self.db.check_cache_valid(url, 'info', max_age_days=3):
                        cached = self.db.get_info_records(url)
                        if cached:
                            Logger.info("Using cached information from PostgreSQL")
                            results.append({
                                'action': 'info_gathering',
                                'status': 'cached',
                                'data': cached,
                                'message': 'Using cached data'
                            })
                            continue
                
                elif action['action'] == 'vulnerability_scan':
                    # Check if cache is valid (less than 3 days old)
                    if self.db.check_cache_valid(url, 'vuln', max_age_days=3):
                        cached = self.db.get_vulnerability_records(url)
                        if cached:
                            Logger.info("Using cached vulnerabilities from PostgreSQL")
                            results.append({
                                'action': 'vulnerability_scan',
                                'status': 'cached',
                                'data': cached,
                                'message': 'Using cached data'
                            })
                            continue
            
            # Execute action
            result = await self.execute_action(action, url)
            results.append(result)
            
            # Check if auto-scan should be triggered (when query_database returns no data)
            if action_name == 'query_database' and result.get('needs_scan') and plan.get('auto_scan_if_empty', False):
                auto_scan_triggered = True
                process_steps.append(f"🔍 No data found, triggering automatic scan...")
                
                # Run info gathering
                process_steps.append(f"⚙️ Executing: info_gathering (auto)...")
                info_result = await self._run_info_gathering(url)
                results.append(info_result)
                if info_result.get('status') == 'success':
                    process_steps.append(f"✓ info_gathering completed successfully")
                else:
                    process_steps.append(f"✗ info_gathering failed: {info_result.get('message', 'Unknown error')}")
                
                # Run vulnerability scan
                process_steps.append(f"⚙️ Executing: vulnerability_scan (auto)...")
                vuln_result = await self._run_vulnerability_scan(url)
                results.append(vuln_result)
                if vuln_result.get('status') == 'success':
                    process_steps.append(f"✓ vulnerability_scan completed successfully")
                    
                    # Re-query database to get filtered results
                    severity_filter = plan.get('severity_filter')
                    if severity_filter:
                        process_steps.append(f"🔍 Filtering vulnerabilities by severity...")
                        filtered_vulns = self.db.get_vulnerability_records(url, severity_filter=severity_filter)
                        result['data'] = {'vulnerabilities': filtered_vulns}
                        result['status'] = 'success'
                        result['needs_scan'] = False
                        if filtered_vulns:
                            result['message'] = f"Found {len(filtered_vulns)} {', '.join(severity_filter).lower()} severity vulnerabilities"
                        else:
                            result['message'] = f"No {', '.join(severity_filter).lower()} severity vulnerabilities found"
                else:
                    process_steps.append(f"✗ vulnerability_scan failed: {vuln_result.get('message', 'Unknown error')}")
            
            # Add completion status
            if result.get('status') == 'success':
                process_steps.append(f"✓ {action_name} completed successfully")
            elif result.get('status') == 'cached':
                process_steps.append(f"✓ {action_name} retrieved from cache")
            elif not auto_scan_triggered:  # Don't show error if we already triggered auto-scan
                process_steps.append(f"✗ {action_name} failed: {result.get('message', 'Unknown error')}")
            
            # Wait for completion if needed
            if action.get('wait_for_completion'):
                await asyncio.sleep(0.1)
        
        # Step 5: Generate summary
        process_steps.append("📝 Generating summary...")
        summary = await self.summarize_results(results)
        process_steps.append("✓ Summary generated")
        
        return {
            'status': 'completed',
            'plan': plan,
            'results': results,
            'response': summary,
            'process_steps': process_steps,
            'needs_confirmation': plan.get('needs_user_confirmation', False),
            'confirmation_message': plan.get('confirmation_message')
        }


# Example usage
async def main():
    agent = SecurityAgent()
    
    # Test messages
    test_messages = [
        "Check security of http://testphp.vulnweb.com",
        "Show me the vulnerabilities",
        "Validate the SQL injection in demo mode"
    ]
    
    for message in test_messages:
        print(f"\n{'='*60}")
        print(f"User: {message}")
        print(f"{'='*60}\n")
        
        result = await agent.process_user_message(message)
        print(f"\nAgent Response:\n{result['response']}")
        print(f"\n{'='*60}\n")


if __name__ == '__main__':
    asyncio.run(main())
