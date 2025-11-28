#!/usr/bin/env python3
"""
Main Entry Point - Cybersecurity AI Agent with LLM Interface
Natural language interface for security testing
"""

import asyncio
import sys
import os

# Import the LLM agent
sys.path.insert(0, os.path.dirname(__file__))
from llm.agent import SecurityAgent
from tools.utils import Logger


def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║      CYBERSECURITY AI AGENT - LLM POWERED INTERFACE      ║
║                                                           ║
║  ⚠️  FOR AUTHORIZED ETHICAL SECURITY TESTING ONLY  ⚠️     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    Logger.banner(banner)
    Logger.info("Natural Language Security Testing Interface")
    Logger.info("Type your security testing requests in plain English")
    print("=" * 60)


async def process_message(agent: SecurityAgent, message: str):
    """Process user message and execute security tests"""
    try:
        Logger.banner("Processing Request")
        Logger.info(f"User: {message}")
        print("=" * 60)
        
        # Process with LLM agent
        result = await agent.process_user_message(message)
        
        # Display results
        Logger.banner("Agent Response")
        print(result['response'])
        print("=" * 60)
        
        # Handle confirmation if needed
        if result.get('needs_confirmation'):
            Logger.warning(result.get('confirmation_message', 'Proceed with exploit validation?'))
            confirm = input("\nContinue? (yes/no): ").strip().lower()
            
            if confirm in ['yes', 'y']:
                Logger.info("Continuing with exploit validation...")
                # Could re-process with confirmation flag
            else:
                Logger.info("Operation cancelled by user")
        
        return True
        
    except Exception as e:
        Logger.error(f"Error processing message: {str(e)}")
        import traceback
        Logger.error(traceback.format_exc())
        return False


async def interactive_mode():
    """Run in interactive mode"""
    print_banner()
    
    # Initialize agent
    Logger.info("Initializing AI agent...")
    agent = SecurityAgent()
    
    Logger.success("Agent initialized! Ready to process security requests.")
    Logger.info("\nExamples:")
    Logger.info("  • 'Scan https://testphp.vulnweb.com for vulnerabilities'")
    Logger.info("  • 'Check security of https://example.com'")
    Logger.info("  • 'Show me vulnerabilities for https://testphp.vulnweb.com'")
    Logger.info("  • 'Validate SQL injection in demo mode'")
    Logger.info("\nType 'exit' or 'quit' to exit.\n")
    
    while True:
        try:
            # Get user input
            user_input = input("\n🔒 You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['exit', 'quit', 'q']:
                Logger.info("Exiting... Goodbye!")
                break
            
            # Process the message
            await process_message(agent, user_input)
            
        except KeyboardInterrupt:
            Logger.warning("\n\nInterrupted by user. Exiting...")
            break
        except Exception as e:
            Logger.error(f"Unexpected error: {str(e)}")


async def single_message_mode(message: str):
    """Process a single message and exit"""
    print_banner()
    
    Logger.info("Initializing AI agent...")
    agent = SecurityAgent()
    success = await process_message(agent, message)
    
    return success


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Cybersecurity AI Agent - LLM Powered Security Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Interactive mode:
    python main.py
    
  Single message mode:
    python main.py -m "Scan https://testphp.vulnweb.com"
    python main.py --message "Check security of https://example.com"

⚠️  LEGAL DISCLAIMER ⚠️
This tool is for authorized security testing only.
Unauthorized access to computer systems is illegal.
        '''
    )
    
    parser.add_argument(
        '-m', '--message',
        help='Single message to process (non-interactive mode)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Cybersecurity AI Agent v2.0.0 (LLM Powered)'
    )
    
    args = parser.parse_args()
    
    try:
        if args.message:
            # Single message mode
            success = asyncio.run(single_message_mode(args.message))
            sys.exit(0 if success else 1)
        else:
            # Interactive mode
            asyncio.run(interactive_mode())
            sys.exit(0)
    
    except Exception as e:
        Logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
