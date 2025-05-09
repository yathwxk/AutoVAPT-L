#!/usr/bin/env python3
"""
Simplified scanner script for AutoVAPT-L using monkey patching for simulation mode
"""

import os
import json
import random
from datetime import datetime
import xml.etree.ElementTree as ET
from typing import Dict, List, Any

from autovaptl.utils.parser import parse_targets
from autovaptl.scanners.nmap_scanner import NmapScanner

def simulate_scan(self, target: str, options: List[str] = None) -> Dict[str, Any]:
    """
    Simulate an Nmap scan without actually running Nmap.
    
    Args:
        target: Target IP address or hostname to scan.
        options: Additional Nmap options.
        
    Returns:
        Dict containing simulated scan results.
    """
    print(f"Simulating Nmap scan for: {target}")
    
    # Create timestamp and output files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")
    output_base = os.path.join(self.output_dir, f"{safe_target}_{timestamp}")
    xml_output = f"{output_base}.xml"
    json_output = f"{output_base}.json"
    
    # Define common ports to include in simulated results
    common_ports = [
        {'port': 22, 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1'},
        {'port': 80, 'service': 'http', 'product': 'Apache httpd', 'version': '2.4.41'},
        {'port': 443, 'service': 'https', 'product': 'Apache httpd', 'version': '2.4.41'},
        {'port': 21, 'service': 'ftp', 'product': 'vsftpd', 'version': '3.0.3'},
        {'port': 3306, 'service': 'mysql', 'product': 'MySQL', 'version': '5.7.30'},
        {'port': 8080, 'service': 'http-proxy', 'product': 'nginx', 'version': '1.18.0'}
    ]
    
    # Randomly select a few ports to include
    num_ports = random.randint(2, 5)
    selected_ports = random.sample(common_ports, num_ports)
    
    # Define some fictional CVEs for vulnerabilities
    cves = [
        {'id': 'CVE-2020-12345', 'cvss': '7.5', 'title': 'Remote Code Execution in Service'},
        {'id': 'CVE-2021-54321', 'cvss': '5.0', 'title': 'Information Disclosure Vulnerability'},
        {'id': 'CVE-2019-98765', 'cvss': '8.8', 'title': 'Privilege Escalation Vulnerability'},
        {'id': 'CVE-2022-56789', 'cvss': '6.2', 'title': 'Cross-Site Scripting Vulnerability'}
    ]
    
    # Build the simulated results
    result = {
        'scan_info': {
            'tcp': {
                'protocol': 'tcp',
                'numservices': '1000'
            }
        },
        'hosts': [
            {
                'addresses': [
                    {
                        'addr': target,
                        'addrtype': 'ipv4'
                    }
                ],
                'hostnames': [
                    {
                        'name': f'host-{target.replace(".", "-")}',
                        'type': 'PTR'
                    }
                ],
                'ports': [],
                'os': [
                    {
                        'name': 'Linux 5.4',
                        'accuracy': '95'
                    }
                ]
            }
        ]
    }
    
    # Add the selected ports and services
    for port_info in selected_ports:
        port_data = {
            'protocol': 'tcp',
            'portid': str(port_info['port']),
            'state': {
                'state': 'open',
                'reason': 'syn-ack'
            },
            'service': {
                'name': port_info['service'],
                'product': port_info['product'],
                'version': port_info['version']
            },
            'scripts': []
        }
        
        # Add vulnerability details for some ports (randomly)
        if random.random() > 0.5:
            script_data = {
                'id': 'vulners',
                'output': 'Vulnerabilities found',
                'vulnerabilities': []
            }
            
            # Add 1-3 random vulnerabilities
            num_vulns = random.randint(1, 3)
            selected_vulns = random.sample(cves, num_vulns)
            
            for vuln in selected_vulns:
                script_data['vulnerabilities'].append({
                    'type': vuln['id'],
                    'data': {
                        'cvss': vuln['cvss'],
                        'title': vuln['title']
                    }
                })
            
            port_data['scripts'].append(script_data)
        
        result['hosts'][0]['ports'].append(port_data)
    
    # Save the simulated JSON results
    with open(json_output, 'w') as f:
        json.dump(result, f, indent=2)
    
    # Generate a simple XML representation for consistency
    root = ET.Element("nmaprun")
    scaninfo = ET.SubElement(root, "scaninfo", type="syn", protocol="tcp", numservices="1000")
    host = ET.SubElement(root, "host")
    
    # Add basic host information
    address = ET.SubElement(host, "address", addr=target, addrtype="ipv4")
    hostnames = ET.SubElement(host, "hostnames")
    hostname = ET.SubElement(hostnames, "hostname", name=f"host-{target.replace('.', '-')}", type="PTR")
    
    # Add ports
    ports = ET.SubElement(host, "ports")
    for port_data in result['hosts'][0]['ports']:
        port = ET.SubElement(ports, "port", protocol=port_data['protocol'], portid=port_data['portid'])
        state = ET.SubElement(port, "state", state=port_data['state']['state'], reason=port_data['state']['reason'])
        service = ET.SubElement(port, "service", name=port_data['service']['name'], 
                              product=port_data['service']['product'], 
                              version=port_data['service']['version'])
        
        # Add scripts
        for script_data in port_data.get('scripts', []):
            script = ET.SubElement(port, "script", id=script_data['id'], output=script_data['output'])
    
    # Save the XML file
    tree = ET.ElementTree(root)
    tree.write(xml_output)
    
    return {
        'target': target,
        'timestamp': timestamp,
        'output_files': {
            'xml': xml_output,
            'json': json_output
        },
        'results': result,
        'simulated': True
    }

def main():
    """
    Main function
    """
    print("AutoVAPT-L: Automated Vulnerability Assessment and Penetration Testing - Lite")
    print("Running with simulation mode\n")
    
    # Create output directory
    output_dir = os.path.join(os.getcwd(), "output")
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize scanner
    scanner = NmapScanner(output_dir=os.path.join(output_dir, "nmap"))
    
    # Replace the original scan method with our simulation function
    scanner.scan = simulate_scan.__get__(scanner, NmapScanner)
    
    # Parse targets
    targets = parse_targets("targets.txt")
    print(f"Found {len(targets['ips'])} IP targets and {len(targets['urls'])} URL targets\n")
    
    # Run simulated scans
    results = []
    for ip in targets['ips']:
        print(f"Scanning IP: {ip}")
        result = scanner.scan(ip)
        results.append(result)
        print(f"Scan completed for {ip}")
    
    # Print summary
    print("\nScan Summary:")
    for result in results:
        print(f"- Scan completed for {result['target']}")
        print(f"  Results saved to: {result['output_files']['json']}")
    
    print("\nAll scans completed successfully.")

if __name__ == "__main__":
    main() 