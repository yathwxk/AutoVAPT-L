"""
Nmap scanner implementation with Vulners NSE script support.
"""

import os
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
import random
import socket
from typing import Dict, List, Optional, Any, Tuple, Set
import logging
import shutil

from ..utils.json_handler import save_json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('nmap_scanner')


class NmapScanner:
    """
    Nmap scanner with Vulners NSE script integration.
    """
    
    def __init__(self, output_dir: str = None, nmap_path: str = "nmap", simulate: bool = False):
        """
        Initialize the Nmap scanner.
        
        Args:
            output_dir: Directory to save scan results.
            nmap_path: Path to the nmap executable.
            simulate: Whether to run in simulation mode.
        """
        self.nmap_path = nmap_path
        self.simulate = simulate
        
        # Set output directory
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(os.getcwd(), "output", "nmap")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Check if Nmap is available, automatically switch to simulation mode if not
        if not self.check_nmap_available() and not self.simulate:
            print("Nmap not found. Automatically switching to simulation mode.")
            self.simulate = True
    
    def check_nmap_available(self) -> bool:
        """
        Check if Nmap is available on the system.
        
        Returns:
            bool: True if Nmap is available, False otherwise.
        """
        if self.simulate:
            return True
            
        try:
            # Run nmap with version flag to check if it's available
            process = subprocess.run(
                [self.nmap_path, "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            
            if process.returncode == 0:
                version_info = process.stdout.strip()
                logger.info(f"Nmap found: {version_info.split('\n')[0]}")
                return True
            else:
                logger.error(f"Nmap check failed with exit code {process.returncode}: {process.stderr}")
                return False
                
        except FileNotFoundError:
            logger.error(f"Nmap not found at path: {self.nmap_path}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout while checking Nmap availability")
            return False
        except Exception as e:
            logger.error(f"Error checking Nmap availability: {str(e)}")
            return False
    
    def _check_vulners_script(self) -> bool:
        """
        Check if the Vulners NSE script is available.
        
        Returns:
            bool: True if the Vulners script is available, False otherwise.
        """
        if self.simulate:
            return True
            
        try:
            process = subprocess.run(
                [self.nmap_path, "--script-help=vulners"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return "vulners" in process.stdout
        except Exception:
            return False
    
    def _generate_simulated_results(self, target: str) -> Dict[str, Any]:
        """
        Generate simulated scan results for testing purposes.
        
        Args:
            target: Target IP address or hostname.
            
        Returns:
            Dict containing simulated scan results.
        """
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
        
        return result
    
    def scan(self, target: str, options: List[str] = None) -> Dict[str, Any]:
        """
        Perform an Nmap scan with Vulners NSE script on the target.
        
        Args:
            target: Target IP address or hostname to scan.
            options: Additional Nmap options.
            
        Returns:
            Dict containing scan results.
        """
        # Check if Nmap is available (skip in simulation mode)
        if not self.simulate and not self.check_nmap_available():
            raise RuntimeError("Nmap is not available. Please install Nmap or check the path.")
            
        # Check if Vulners script is available (skip in simulation mode)
        vulners_available = self.simulate or self._check_vulners_script()
        if not vulners_available and not self.simulate:
            print("Warning: Vulners NSE script is not available. Vulnerability detection will be limited.")
        
        # Create timestamp and output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(":", "_").replace("/", "_")
        output_base = os.path.join(self.output_dir, f"{safe_target}_{timestamp}")
        xml_output = f"{output_base}.xml"
        json_output = f"{output_base}.json"
        
        if self.simulate:
            print(f"Simulating Nmap scan for: {target}")
            results = self._generate_simulated_results(target)
            
            # Save the simulated JSON results using our utility
            save_json(results, json_output)
                
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
            for port_data in results['hosts'][0]['ports']:
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
                'results': results,
                'simulated': True
            }
        
        # If not in simulation mode, run the actual Nmap scan
        # Prepare Nmap command
        cmd = [self.nmap_path, "-oX", xml_output]
        
        # Add Vulners script if available
        if vulners_available:
            cmd.append("--script=vulners")
        
        # Add additional options if provided
        if options:
            cmd.extend(options)
        
        # Add target
        cmd.append(target)
        
        print(f"Running Nmap scan: {' '.join(cmd)}")
        
        # Run the scan
        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if process.returncode != 0:
                print(f"Warning: Nmap scan had non-zero exit code: {process.returncode}")
                print(f"Error output: {process.stderr}")
            
            # Parse the XML output into JSON
            results = self._parse_xml_to_json(xml_output)
            
            # Save the JSON results using our utility
            save_json(results, json_output)
                
            return {
                'target': target,
                'timestamp': timestamp,
                'output_files': {
                    'xml': xml_output,
                    'json': json_output
                },
                'results': results
            }
            
        except Exception as e:
            print(f"Error scanning {target}: {str(e)}")
            return {
                'target': target,
                'timestamp': timestamp,
                'error': str(e)
            }
    
    def _parse_xml_to_json(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output to a JSON-compatible dictionary.
        
        Args:
            xml_file: Path to the XML file.
            
        Returns:
            Dict containing parsed results.
        """
        if not os.path.exists(xml_file):
            return {'error': 'XML file not found'}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            result = {
                'scan_info': {},
                'hosts': []
            }
            
            # Parse scan info
            if root.find('scaninfo') is not None:
                for info in root.findall('scaninfo'):
                    result['scan_info'][info.get('type')] = {
                        'protocol': info.get('protocol'),
                        'numservices': info.get('numservices')
                    }
            
            # Parse hosts
            for host in root.findall('host'):
                host_data = {
                    'addresses': [],
                    'hostnames': [],
                    'ports': [],
                    'os': []
                }
                
                # Parse addresses
                for addr in host.findall('address'):
                    host_data['addresses'].append({
                        'addr': addr.get('addr'),
                        'addrtype': addr.get('addrtype')
                    })
                
                # Parse hostnames
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall('hostname'):
                        host_data['hostnames'].append({
                            'name': hostname.get('name'),
                            'type': hostname.get('type')
                        })
                
                # Parse ports and services
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_data = {
                            'protocol': port.get('protocol'),
                            'portid': port.get('portid'),
                            'state': {},
                            'service': {},
                            'scripts': []
                        }
                        
                        # Parse state
                        state_elem = port.find('state')
                        if state_elem is not None:
                            port_data['state'] = {
                                'state': state_elem.get('state'),
                                'reason': state_elem.get('reason')
                            }
                        
                        # Parse service
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_data = {
                                'name': service_elem.get('name'),
                                'product': service_elem.get('product'),
                                'version': service_elem.get('version'),
                                'extrainfo': service_elem.get('extrainfo'),
                                'ostype': service_elem.get('ostype')
                            }
                            # Remove None values
                            port_data['service'] = {k: v for k, v in service_data.items() if v is not None}
                        
                        # Parse scripts (including Vulners)
                        for script in port.findall('script'):
                            script_data = {
                                'id': script.get('id'),
                                'output': script.get('output'),
                                'tables': []
                            }
                            
                            # Handle vulners script specially to extract CVEs
                            if script.get('id') == 'vulners':
                                script_data['vulnerabilities'] = []
                                for table in script.findall('table'):
                                    vuln = {
                                        'type': table.get('key'),
                                        'data': {}
                                    }
                                    
                                    for elem in table.findall('elem'):
                                        vuln['data'][elem.get('key')] = elem.text
                                    
                                    script_data['vulnerabilities'].append(vuln)
                            
                            port_data['scripts'].append(script_data)
                        
                        host_data['ports'].append(port_data)
                
                # Parse OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    for match in os_elem.findall('osmatch'):
                        os_data = {
                            'name': match.get('name'),
                            'accuracy': match.get('accuracy')
                        }
                        host_data['os'].append(os_data)
                
                result['hosts'].append(host_data)
            
            return result
            
        except Exception as e:
            return {'error': f'Failed to parse XML: {str(e)}'} 