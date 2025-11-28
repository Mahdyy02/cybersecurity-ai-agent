#!/usr/bin/env python3
"""
Utility functions for the cybersecurity tools
"""

import os
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for Windows support
init(autoreset=True)

class Logger:
    """Simple logger with color support"""
    
    @staticmethod
    def info(message):
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def success(message):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def warning(message):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def error(message):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")
    
    @staticmethod
    def banner(message):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{message}")
        print(f"{'='*60}{Style.RESET_ALL}\n")


def ensure_directory(path):
    """Ensure directory exists"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        Logger.error(f"Failed to create directory {path}: {str(e)}")
        return False


def get_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()


def format_datetime(dt_string):
    """Format datetime string for display"""
    try:
        dt = datetime.fromisoformat(dt_string)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return dt_string


def validate_url(url):
    """Validate URL format"""
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def sanitize_filename(filename):
    """Sanitize filename by removing invalid characters"""
    import re
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    return filename


def read_csv_file(filepath):
    """Read CSV file and return list of dictionaries"""
    import csv
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        Logger.error(f"Failed to read CSV file {filepath}: {str(e)}")
        return []


def write_csv_file(filepath, data, fieldnames):
    """Write data to CSV file"""
    import csv
    try:
        ensure_directory(os.path.dirname(filepath))
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        return True
    except Exception as e:
        Logger.error(f"Failed to write CSV file {filepath}: {str(e)}")
        return False


def print_summary_table(data, title="Summary"):
    """Print a formatted summary table"""
    Logger.banner(title)
    
    if not data:
        print("No data to display")
        return
    
    # Calculate column widths
    if isinstance(data, dict):
        max_key_len = max(len(str(k)) for k in data.keys())
        max_val_len = max(len(str(v)) for v in data.values())
        
        for key, value in data.items():
            print(f"{str(key).ljust(max_key_len)} : {value}")
    
    elif isinstance(data, list) and data:
        # Print first few items
        for i, item in enumerate(data[:10]):
            print(f"{i+1}. {item}")
        
        if len(data) > 10:
            print(f"... and {len(data) - 10} more items")


def check_docker_available():
    """Check if Docker is available"""
    import subprocess
    try:
        result = subprocess.run(['docker', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except:
        return False


def check_wsl_available():
    """Check if WSL is available (Windows only)"""
    if sys.platform != 'win32':
        return False
    
    import subprocess
    try:
        result = subprocess.run(['wsl', '--status'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except:
        return False


class ProgressBar:
    """Simple progress bar"""
    
    def __init__(self, total, prefix='Progress:', length=40):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0
    
    def update(self, amount=1):
        self.current += amount
        self._print()
    
    def _print(self):
        percent = (self.current / self.total) * 100
        filled = int(self.length * self.current / self.total)
        bar = '█' * filled + '-' * (self.length - filled)
        
        print(f'\r{self.prefix} |{bar}| {percent:.1f}% Complete', end='')
        
        if self.current >= self.total:
            print()  # New line when complete


def parse_severity(severity_str):
    """Parse severity string to numeric value"""
    severity_map = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    }
    return severity_map.get(severity_str.lower(), 0)


def generate_report_summary(vulnerabilities):
    """Generate summary statistics from vulnerabilities"""
    if not vulnerabilities:
        return {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }
    
    summary = {
        'total': len(vulnerabilities),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'by_type': {}
    }
    
    for vuln in vulnerabilities:
        # Count by severity
        severity = vuln.get('Severity', '').lower()
        if severity == 'critical':
            summary['critical'] += 1
        elif severity == 'high':
            summary['high'] += 1
        elif severity == 'medium':
            summary['medium'] += 1
        elif severity == 'low':
            summary['low'] += 1
        
        # Count by type
        vuln_type = vuln.get('Type', 'Unknown')
        summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
    
    return summary
