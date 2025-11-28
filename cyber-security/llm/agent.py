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
            if action_name == 'info_gathering':
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
        """Summarize results using LLM"""
        Logger.info("Generating summary...")
        
        try:
            # Prepare condensed data for summarization
            summary_parts = []
            
            for result in results:
                action = result.get('action', 'unknown')
                status = result.get('status', 'unknown')
                message = result.get('message', '')
                data = result.get('data', [])
                
                # Create a condensed summary for each action
                if action == 'info_gathering':
                    data_count = len(data) if data else 0
                    summary_parts.append(f"✓ Information Gathering: {status.upper()} - {data_count} records collected")
                    
                elif action == 'vulnerability_scan':
                    vuln_count = len(data) if data else 0
                    summary_parts.append(f"✓ Vulnerability Scan: {status.upper()} - {vuln_count} issues found")
                    
                elif action == 'exploit_validation':
                    exploit_count = len(data) if data else 0
                    summary_parts.append(f"✓ Exploit Validation: {status.upper()} - {exploit_count} validated")
                    
                elif action in ['display_info', 'display_vulnerabilities']:
                    data_count = len(data) if data else 0
                    summary_parts.append(f"✓ {action}: {status.upper()} - {data_count} records retrieved")
            
            # Create compact summary for LLM
            summary_text = "\n".join(summary_parts)
            summary_text += f"\n\nTotal actions completed: {len(results)}"
            
            # Call LLM with condensed summary
            response = await generate_chatbot_response(
                system_prompt=RESULT_SUMMARIZER_PROMPT,
                user_message=f"Security scan results:\n{summary_text}",
                temperature=0.5,
                max_tokens=500
            )
            
            if response and response != "None":
                return response
            else:
                # Fallback to simple summary
                return summary_text
        
        except Exception as e:
            Logger.error(f"Summarization error: {str(e)}")
            # Return a basic summary as fallback
            summary = []
            for result in results:
                summary.append(f"{result.get('action', 'Action')}: {result.get('message', 'No message')}")
            return "\n".join(summary) if summary else "Operations completed."
    
    async def process_user_message(self, user_message: str) -> Dict:
        """
        Main entry point: Process user message and execute plan
        Returns execution results and response for user
        """
        Logger.banner("Processing User Message")
        
        # Step 1: Extract URL
        url = await self.extract_url(user_message)
        if url:
            self.current_url = url
        elif self.current_url:
            url = self.current_url
        
        # Step 2: Analyze intent and create plan
        plan = await self.analyze_intent(user_message, url)
        
        # Step 3: Check if immediate response needed
        if plan.get('display_to_user') and not plan.get('actions'):
            return {
                'status': 'completed',
                'plan': plan,
                'results': [],
                'response': plan['display_to_user']
            }
        
        # Step 4: Execute actions
        results = []
        for action in plan.get('actions', []):
            if not url:
                results.append({
                    'action': action.get('action'),
                    'status': 'error',
                    'message': 'No URL provided'
                })
                continue
            
            # Check database if needed
            if plan.get('check_database'):
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
            
            # Wait for completion if needed
            if action.get('wait_for_completion'):
                await asyncio.sleep(0.1)
        
        # Step 5: Generate summary
        summary = await self.summarize_results(results)
        
        return {
            'status': 'completed',
            'plan': plan,
            'results': results,
            'response': summary,
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
