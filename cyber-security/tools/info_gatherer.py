#!/usr/bin/env python3
"""
Information Gathering Tool
Collects comprehensive website information using FinalRecon and other techniques
Outputs results to CSV format
"""

import subprocess
import json
import csv
import argparse
import sys
import os
import socket
from datetime import datetime
from urllib.parse import urlparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

class InfoGatherer:
    def __init__(self, target_url, output_file):
        self.target_url = target_url
        self.output_file = output_file
        self.results = []
        
    def validate_url(self):
        """Validate the target URL"""
        try:
            result = urlparse(self.target_url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def run_finalrecon(self):
        """
        Execute FinalRecon using Docker
        Command: docker run --rm finalrecon --full --url <target_url>
        """
        print(f"[*] Running FinalRecon on {self.target_url}...")
        
        try:
            # Build the docker command for Windows/WSL
            cmd = [
                'docker', 'run', '--rm', 
                'finalrecon', 
                '--full', 
                '--url', self.target_url
            ]
            
            # Execute FinalRecon
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if process.returncode != 0:
                print(f"[!] FinalRecon error: {stderr}")
                return None
            
            print("[+] FinalRecon completed successfully")

            print(f"[DEBUG] FinalRecon output:\n{stdout}")

            return stdout
            
        except subprocess.TimeoutExpired:
            process.kill()
            print("[!] FinalRecon timed out")
            return None
        except Exception as e:
            print(f"[!] Error running FinalRecon: {str(e)}")
            return None
    
    def parse_finalrecon_output(self, output):
        """Parse FinalRecon output and extract structured data"""
        if not output:
            return []
        
        data = []
        current_section = "General"
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('['):
                continue
            
            # Detect section headers
            if line.isupper() or line.endswith(':'):
                current_section = line.rstrip(':')
                continue
            
            # Parse key-value pairs
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    data.append({
                        'Category': current_section,
                        'Key': key,
                        'Value': value,
                        'Timestamp': datetime.now().isoformat()
                    })
        
        return data
    
    def gather_basic_info(self):
        """Gather basic information about the target"""
        print("[*] Gathering basic information...")
        
        parsed_url = urlparse(self.target_url)
        
        basic_info = [
            {
                'Category': 'Target Information',
                'Key': 'URL',
                'Value': self.target_url,
                'Timestamp': datetime.now().isoformat()
            },
            {
                'Category': 'Target Information',
                'Key': 'Domain',
                'Value': parsed_url.netloc,
                'Timestamp': datetime.now().isoformat()
            },
            {
                'Category': 'Target Information',
                'Key': 'Scheme',
                'Value': parsed_url.scheme,
                'Timestamp': datetime.now().isoformat()
            },
            {
                'Category': 'Target Information',
                'Key': 'Path',
                'Value': parsed_url.path or '/',
                'Timestamp': datetime.now().isoformat()
            }
        ]
        
        return basic_info
    
    def gather_http_headers(self):
        """Gather HTTP headers from the target"""
        print("[*] Gathering HTTP headers...")
        
        try:
            import requests
            response = requests.get(self.target_url, timeout=10, verify=False, 
                                   allow_redirects=True)
            
            headers_data = []
            for header, value in response.headers.items():
                headers_data.append({
                    'Category': 'HTTP Headers',
                    'Key': header,
                    'Value': value,
                    'Timestamp': datetime.now().isoformat()
                })
            
            # Add status code
            headers_data.append({
                'Category': 'HTTP Response',
                'Key': 'Status Code',
                'Value': str(response.status_code),
                'Timestamp': datetime.now().isoformat()
            })
            
            return headers_data
        except Exception as e:
            print(f"[!] Error gathering HTTP headers: {str(e)}")
            return []
    
    def gather_dns_info(self):
        """Gather DNS information"""
        print("[*] Gathering DNS information...")
        
        try:
            import dns.resolver
            parsed_url = urlparse(self.target_url)
            domain = parsed_url.netloc
            
            dns_data = []
            
            # Query A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for rdata in answers:
                    dns_data.append({
                        'Category': 'DNS Records',
                        'Key': 'A Record',
                        'Value': str(rdata),
                        'Timestamp': datetime.now().isoformat()
                    })
            except:
                pass
            
            # Query MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                for rdata in answers:
                    dns_data.append({
                        'Category': 'DNS Records',
                        'Key': 'MX Record',
                        'Value': str(rdata),
                        'Timestamp': datetime.now().isoformat()
                    })
            except:
                pass
            
            # Query NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                for rdata in answers:
                    dns_data.append({
                        'Category': 'DNS Records',
                        'Key': 'NS Record',
                        'Value': str(rdata),
                        'Timestamp': datetime.now().isoformat()
                    })
            except:
                pass
            
            return dns_data
        except Exception as e:
            print(f"[!] Error gathering DNS info: {str(e)}")
            return []
    
    def scan_port(self, host, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def get_service_name(self, port):
        """Get common service name for a port"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
        }
        return common_ports.get(port, 'Unknown')
    
    def scan_ports(self):
        """Scan common ports on the target"""
        print("[*] Scanning open ports...")
        
        try:
            parsed_url = urlparse(self.target_url)
            host = parsed_url.netloc.split(':')[0]  # Remove port if specified in URL
            
            # Resolve hostname to IP
            try:
                ip_address = socket.gethostbyname(host)
                print(f"[*] Resolved {host} to {ip_address}")
            except socket.gaierror:
                print(f"[!] Could not resolve hostname: {host}")
                return []
            
            # Common ports to scan
            common_ports = [
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
                993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
            ]
            
            port_data = []
            open_ports = []
            
            print(f"[*] Scanning {len(common_ports)} common ports...")
            
            # Use ThreadPoolExecutor for concurrent port scanning
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, ip_address, port): port 
                    for port in common_ports
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result is not None:
                            open_ports.append(result)
                            service = self.get_service_name(result)
                            port_data.append({
                                'Category': 'Open Ports',
                                'Key': f'Port {result}',
                                'Value': f'{service} (Open)',
                                'Timestamp': datetime.now().isoformat()
                            })
                            print(f"[+] Port {result} is open ({service})")
                    except Exception as e:
                        pass
            
            if open_ports:
                # Add summary
                port_data.append({
                    'Category': 'Port Scan Summary',
                    'Key': 'Total Open Ports',
                    'Value': str(len(open_ports)),
                    'Timestamp': datetime.now().isoformat()
                })
                port_data.append({
                    'Category': 'Port Scan Summary',
                    'Key': 'Open Ports List',
                    'Value': ', '.join(map(str, sorted(open_ports))),
                    'Timestamp': datetime.now().isoformat()
                })
                print(f"[+] Found {len(open_ports)} open ports: {', '.join(map(str, sorted(open_ports)))}")
            else:
                port_data.append({
                    'Category': 'Port Scan Summary',
                    'Key': 'Result',
                    'Value': 'No common ports found open',
                    'Timestamp': datetime.now().isoformat()
                })
                print("[!] No open ports found")
            
            return port_data
            
        except Exception as e:
            print(f"[!] Error scanning ports: {str(e)}")
            return []
    
    def save_to_csv(self, data):
        """Save gathered information to CSV"""
        if not data:
            print("[!] No data to save")
            return False
        
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            # Write to CSV
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['Category', 'Key', 'Value', 'Timestamp']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                writer.writerows(data)
            
            print(f"[+] Results saved to {self.output_file}")
            return True
        except Exception as e:
            print(f"[!] Error saving to CSV: {str(e)}")
            return False
    
    def run(self):
        """Main execution method"""
        print("="*60)
        print("Information Gathering Tool")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Output: {self.output_file}")
        print("="*60)
        
        # Validate URL
        if not self.validate_url():
            print("[!] Invalid URL format")
            return False
        
        # Gather basic information
        self.results.extend(self.gather_basic_info())
        
        # Gather HTTP headers
        self.results.extend(self.gather_http_headers())
        
        # Gather DNS information
        self.results.extend(self.gather_dns_info())
        
        # Scan ports
        self.results.extend(self.scan_ports())
        
        # FinalRecon, houni ynajjem yfaili ken el Docker image is not available
        finalrecon_output = self.run_finalrecon()
        if finalrecon_output:
            finalrecon_data = self.parse_finalrecon_output(finalrecon_output)
            self.results.extend(finalrecon_data)
        else:
            print("[!] FinalRecon not available, continuing with basic gathering...")
        
        # Save results
        if self.save_to_csv(self.results):
            print(f"\n[+] Information gathering completed")
            print(f"[+] Total entries: {len(self.results)}")
            return True
        
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Information Gathering Tool - Collects website information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python info_gatherer.py --url https://example.com --output results/info.csv
  python info_gatherer.py -u http://testsite.local -o output.csv
        '''
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output CSV file path'
    )
    
    args = parser.parse_args()
    
    # Run the tool
    gatherer = InfoGatherer(args.url, args.output)
    success = gatherer.run()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
