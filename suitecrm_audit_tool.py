#!/usr/bin/env python3
"""
SuiteCRM Security Audit Tool
============================

A comprehensive security auditing tool for SuiteCRM instances that:
- Detects SuiteCRM versions via public API
- Matches against real CVE database
- Performs non-destructive vulnerability testing
- Supports batch processing for large-scale audits
- Generates detailed security reports

Author: Security Audit Team
Version: 2.0
Date: October 2025
"""

import requests
import sys
import urllib3
import ssl
import re
import time
import random
import string
import json
import csv
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for internal audits
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Real SuiteCRM CVE Database (Updated Oct 2025)
SUITECRM_CVES = {
    "8.9.0": {
        "cves": [
            # Latest version - most CVEs patched
        ]
    },
    "8.8.1": {
        "cves": [
            # Patched version
        ]
    },
    "8.8.0": {
        "cves": [
            {
                "id": "CVE-2025-54785",
                "severity": "HIGH",
                "description": "Unvalidated input to unserialize(), leading to privilege escalation, DoS, or ransomware",
                "cvss": "8.6",
                "version_range": "<=8.8.0",
                "requires_auth": False,
                "endpoints": ["/legacy/service/v4_1/rest.php", "/service/v4_1/rest.php"],
                "payloads": {
                    "deserialization": [
                        "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
                        "a:1:{i:0;s:4:\"test\";}"
                    ]
                }
            },
            {
                "id": "CVE-2025-54786",
                "severity": "MEDIUM", 
                "description": "Broken auth in legacy iCal service; unauth access to meetings/user enumeration",
                "cvss": "5.1",
                "version_range": "<=8.8.0",
                "requires_auth": False,
                "endpoints": ["/legacy/index.php?module=iCals&action=index"],
                "payloads": {
                    "auth_bypass": [
                        "?module=iCals&action=index&record=",
                        "?module=iCals&action=index&user_id=1"
                    ]
                }
            }
        ]
    },
    "8.7.1": {
        "cves": [
            {
                "id": "CVE-2024-50335",
                "severity": "MEDIUM",
                "description": "Reflected XSS in 'Publish Key' field on Edit Profile, enabling CSRF token theft and admin user creation",
                "cvss": "6.1",
                "version_range": "<8.7.1",
                "requires_auth": True,
                "endpoints": ["/index.php?module=Users&action=EditView"],
                "payloads": {
                    "xss": [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>"
                    ]
                }
            }
        ]
    },
    "8.6.2": {
        "cves": [
            {
                "id": "CVE-2024-45392",
                "severity": "MEDIUM",
                "description": "Improper access control allowing unauthorized record deletion via API",
                "cvss": "5.3",
                "version_range": "<8.6.2",
                "requires_auth": True,
                "endpoints": ["/service/v4_1/rest.php?method=set_entry"],
                "payloads": {
                    "access_control": [
                        "{\"module_name\":\"Accounts\",\"name_value_list\":[{\"name\":\"id\",\"value\":\"1\"}],\"deleted\":1}"
                    ]
                }
            }
        ]
    },
    "8.6.1": {
        "cves": [
            {
                "id": "CVE-2024-36408",
                "severity": "MEDIUM",
                "description": "SQL Injection in Alerts controller due to poor input validation",
                "cvss": "6.5",
                "version_range": "<8.6.1",
                "requires_auth": True,
                "endpoints": ["/index.php?module=Alerts&action=index"],
                "payloads": {
                    "sql_injection": [
                        "' OR SLEEP(5)--",
                        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                        "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--"
                    ]
                }
            },
            {
                "id": "CVE-2024-36410",
                "severity": "MEDIUM",
                "description": "SQL Injection in EmailUIAjax messages count controller",
                "cvss": "6.5",
                "version_range": "<8.6.1",
                "requires_auth": True,
                "endpoints": ["/index.php?module=EmailUIAjax&action=messages_count"],
                "payloads": {
                    "sql_injection": [
                        "' OR SLEEP(5)--",
                        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
                    ]
                }
            }
        ]
    },
    "7.14.7": {
        "cves": [
            # Latest 7.x version - most CVEs patched
        ]
    },
    "7.14.6": {
        "cves": [
            {
                "id": "CVE-2025-54783",
                "severity": "MEDIUM",
                "description": "Reflected XSS via manipulated HTTP Referer header",
                "cvss": "5.1",
                "version_range": "<=7.14.6",
                "requires_auth": False,
                "endpoints": ["/index.php"],
                "payloads": {
                    "xss": [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>"
                    ]
                }
            },
            {
                "id": "CVE-2025-54784",
                "severity": "HIGH",
                "description": "Stored XSS in email viewer; external attacker sends malicious email, executes on view",
                "cvss": "8.6",
                "version_range": "7.14.0-7.14.6",
                "requires_auth": True,
                "endpoints": ["/index.php?module=Emails&action=DetailView"],
                "payloads": {
                    "stored_xss": [
                        "<script>alert('Stored XSS')</script>",
                        "<img src=x onerror=alert('Stored XSS')>"
                    ]
                }
            },
            {
                "id": "CVE-2025-54787",
                "severity": "MEDIUM",
                "description": "Unauth file downloads from upload dir via brute-forced UUID IDs",
                "cvss": "5.3",
                "version_range": "<=7.14.6",
                "requires_auth": False,
                "endpoints": ["/index.php?module=Documents&action=DownloadAttachment"],
                "payloads": {
                    "information_disclosure": [
                        "?id=00000000-0000-0000-0000-000000000001",
                        "?id=00000000-0000-0000-0000-000000000002"
                    ]
                }
            }
        ]
    }
}

class SuiteCRMAuditor:
    def __init__(self, ssl_verify=False, max_workers=10, timeout=30):
        self.ssl_verify = ssl_verify
        self.max_workers = max_workers
        self.timeout = timeout
        self.results = []
        
    def create_session(self):
        """Create a requests session with proper SSL and retry configuration"""
        session = requests.Session()
        session.verify = self.ssl_verify
        
        # Add retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def normalize_url(self, url):
        """Normalize URL and fix common issues"""
        url = url.strip().rstrip('/')
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        # Fix double slashes
        url = re.sub(r'(?<!:)//+', '/', url)
        return url
    
    def extract_version_from_string(self, version_string):
        """Extract SuiteCRM version from version string"""
        version_patterns = [
            r'SuiteCRM Version: ([\d.]+)',
            r'Version: ([\d.]+)',
            r'([\d]+\.[\d]+\.[\d]+)',
            r'([\d]+\.[\d]+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, version_string)
            if match:
                return match.group(1)
        return None
    
    def find_matching_version(self, version):
        """Find the best matching version in our CVE database"""
        if not version:
            return None
        
        # Try exact match first
        if version in SUITECRM_CVES:
            return version
        
        # Try major.minor match
        major_minor = '.'.join(version.split('.')[:2])
        for v in SUITECRM_CVES.keys():
            if v.startswith(major_minor):
                return v
        
        # Try major version match
        major = version.split('.')[0]
        for v in SUITECRM_CVES.keys():
            if v.startswith(major + '.'):
                return v
        
        return None
    
    def get_suitecrm_version(self, base_url):
        """Detect SuiteCRM version via API"""
        session = self.create_session()
        
        # Define API endpoints to try
        extractors = [
            "service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON",
            "legacy/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON",
            "service/v4/rest.php?method=get_server_info&input_type=JSON&response_type=JSON",
            "service/v2/rest.php?method=get_server_info&input_type=JSON&response_type=JSON"
        ]
        
        for extractor in extractors:
            api_url = f"{base_url}/{extractor}"
            try:
                response = session.get(api_url, timeout=self.timeout)
                if response.status_code == 200:
                    try:
                        info = response.json()
                        if 'version' in info:
                            suite_version = info.get('suitecrm_version', 'Not specified')
                            sugar_version = info.get('version', 'Unknown')
                            flavor = info.get('flavor', 'Unknown')
                            gmt_time = info.get('gmt_time', 'Unknown')
                            
                            if flavor == 'CE' and suite_version != 'Not specified':
                                return f"SuiteCRM Version: {suite_version} (SugarCRM base: {sugar_version}, GMT Time: {gmt_time})"
                            elif flavor == 'CE':
                                return f"SugarCRM CE Version: {sugar_version} (likely SuiteCRM, GMT Time: {gmt_time})"
                            else:
                                return f"Flavor: {flavor}, Version: {sugar_version} (GMT Time: {gmt_time})"
                    except ValueError:
                        pass  # Not JSON
            except Exception:
                continue
        
        # Try POST requests
        post_endpoints = ['/service/v4_1/rest.php', '/legacy/service/v4_1/rest.php']
        data = {
            'method': 'get_server_info',
            'input_type': 'JSON',
            'response_type': 'JSON'
        }
        
        for endpoint in post_endpoints:
            api_url = base_url + endpoint
            try:
                response = session.post(api_url, data=data, timeout=self.timeout)
                if response.status_code == 200:
                    try:
                        info = response.json()
                        if 'version' in info:
                            suite_version = info.get('suitecrm_version', 'Not specified')
                            sugar_version = info.get('version', 'Unknown')
                            flavor = info.get('flavor', 'Unknown')
                            gmt_time = info.get('gmt_time', 'Unknown')
                            
                            if flavor == 'CE' and suite_version != 'Not specified':
                                return f"SuiteCRM Version: {suite_version} (SugarCRM base: {sugar_version}, GMT Time: {gmt_time})"
                            elif flavor == 'CE':
                                return f"SugarCRM CE Version: {sugar_version} (likely SuiteCRM, GMT Time: {gmt_time})"
                            else:
                                return f"Flavor: {flavor}, Version: {sugar_version} (GMT Time: {gmt_time})"
                    except ValueError:
                        pass
            except Exception:
                continue
        
        return "Could not retrieve version. The site may not be SuiteCRM, the API may be disabled, or authentication may be required."
    
    def test_sql_injection_safe(self, base_url, endpoint, payload, session):
        """Test SQL injection using non-destructive time-based detection"""
        try:
            # Use time-based detection instead of destructive payloads
            start_time = time.time()
            
            # Test with time-based payload
            test_url = f"{base_url}{endpoint}"
            params = {'search_name': payload}
            
            response = session.get(test_url, params=params, timeout=self.timeout)
            end_time = time.time()
            
            # Check for significant delay (indicating SQL injection)
            if end_time - start_time > 4:  # 5 second delay in payload
                return True, f"Time-based SQL injection detected (delay: {end_time - start_time:.2f}s)"
            
            # Check for error indicators
            error_indicators = [
                "mysql_fetch_array", "mysql_num_rows", "mysql_query",
                "Warning: mysql", "MySQL Error", "SQL syntax",
                "database error", "mysql_connect", "mysqli_",
                "PDOException", "SQLSTATE"
            ]
            
            response_text = response.text.lower()
            for indicator in error_indicators:
                if indicator.lower() in response_text:
                    return True, f"SQL Error detected: {indicator}"
            
            return False, "No SQL injection detected"
            
        except Exception as e:
            return False, f"Error: {str(e)[:100]}"
    
    def test_xss_safe(self, base_url, endpoint, payload, session):
        """Test XSS using safe reflection detection"""
        try:
            test_url = f"{base_url}{endpoint}"
            params = {'search_name': payload}
            
            response = session.get(test_url, params=params, timeout=self.timeout)
            
            # Check if payload is reflected (safe test)
            if payload in response.text:
                return True, f"XSS payload reflected in response"
            
            return False, "No XSS reflection detected"
            
        except Exception as e:
            return False, f"Error: {str(e)[:100]}"
    
    def test_information_disclosure_safe(self, base_url, endpoint, session):
        """Test information disclosure safely"""
        try:
            test_url = f"{base_url}{endpoint}"
            response = session.get(test_url, timeout=self.timeout)
            
            if response.status_code == 200:
                sensitive_patterns = [
                    "password", "database", "config", "mysql",
                    "hostname", "version", "api_key", "secret", "token"
                ]
                
                response_text = response.text.lower()
                found_patterns = [p for p in sensitive_patterns if p in response_text]
                
                if found_patterns:
                    return True, f"Information disclosed: {', '.join(found_patterns)}"
                else:
                    return False, "No sensitive information disclosed"
            else:
                return False, f"Endpoint not accessible: {response.status_code}"
                
        except Exception as e:
            return False, f"Error: {str(e)[:100]}"
    
    def test_vulnerability(self, base_url, cve, session):
        """Test a specific vulnerability safely"""
        cve_id = cve['id']
        cve_type = cve.get('payloads', {}).keys()
        endpoints = cve.get('endpoints', [])
        
        results = []
        
        for endpoint in endpoints[:2]:  # Limit to first 2 endpoints
            for payload_type, payloads in cve.get('payloads', {}).items():
                for payload in payloads[:2]:  # Limit to first 2 payloads
                    if payload_type == "sql_injection":
                        success, result = self.test_sql_injection_safe(base_url, endpoint, payload, session)
                    elif payload_type in ["xss", "stored_xss"]:
                        success, result = self.test_xss_safe(base_url, endpoint, payload, session)
                    elif payload_type == "information_disclosure":
                        success, result = self.test_information_disclosure_safe(base_url, endpoint, session)
                    else:
                        # For other types, just test basic connectivity
                        try:
                            test_url = f"{base_url}{endpoint}"
                            response = session.get(test_url, timeout=self.timeout)
                            success = response.status_code == 200
                            result = f"Endpoint accessible: {response.status_code}"
                        except:
                            success = False
                            result = "Endpoint not accessible"
                    
                    if success:
                        results.append({
                            'cve_id': cve_id,
                            'endpoint': endpoint,
                            'payload_type': payload_type,
                            'payload': payload,
                            'result': result
                        })
        
        return results
    
    def audit_single_target(self, url):
        """Audit a single SuiteCRM target"""
        try:
            normalized_url = self.normalize_url(url)
            session = self.create_session()
            
            print(f"🔍 Auditing: {normalized_url}")
            
            # Get version
            version_info = self.get_suitecrm_version(normalized_url)
            detected_version = self.extract_version_from_string(version_info)
            matching_version = self.find_matching_version(detected_version)
            
            result = {
                'url': normalized_url,
                'version_info': version_info,
                'detected_version': detected_version,
                'matching_version': matching_version,
                'vulnerabilities': [],
                'status': 'success' if detected_version else 'failed'
            }
            
            if matching_version and matching_version in SUITECRM_CVES:
                cves = SUITECRM_CVES[matching_version]["cves"]
                
                for cve in cves:
                    vuln_results = self.test_vulnerability(normalized_url, cve, session)
                    if vuln_results:
                        result['vulnerabilities'].extend(vuln_results)
            
            return result
            
        except Exception as e:
            return {
                'url': url,
                'version_info': f"Error: {str(e)}",
                'detected_version': None,
                'matching_version': None,
                'vulnerabilities': [],
                'status': 'error'
            }
    
    def audit_batch(self, urls):
        """Audit multiple targets in parallel"""
        print(f"🚀 Starting batch audit of {len(urls)} targets...")
        print(f"⚙️  Using {self.max_workers} workers, SSL verify: {self.ssl_verify}")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.audit_single_target, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print progress
                    vuln_count = len(result['vulnerabilities'])
                    status_icon = "✅" if result['status'] == 'success' else "❌"
                    print(f"{status_icon} {url} - {vuln_count} vulnerabilities found")
                    
                except Exception as e:
                    print(f"❌ {url} - Error: {str(e)}")
                    results.append({
                        'url': url,
                        'version_info': f"Error: {str(e)}",
                        'detected_version': None,
                        'matching_version': None,
                        'vulnerabilities': [],
                        'status': 'error'
                    })
        
        return results
    
    def generate_report(self, results, output_file="suitecrm_audit_report.json"):
        """Generate detailed audit report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_targets': len(results),
            'successful_scans': len([r for r in results if r['status'] == 'success']),
            'failed_scans': len([r for r in results if r['status'] != 'success']),
            'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in results),
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📊 Report saved to: {output_file}")
        return report
    
    def generate_csv_summary(self, results, output_file="suitecrm_audit_summary.csv"):
        """Generate CSV summary for easy analysis"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status', 'Detected Version', 'Vulnerability Count', 'Vulnerabilities'])
            
            for result in results:
                vuln_count = len(result['vulnerabilities'])
                vuln_list = '; '.join([f"{v['cve_id']}:{v['payload_type']}" for v in result['vulnerabilities']])
                
                writer.writerow([
                    result['url'],
                    result['status'],
                    result['detected_version'] or 'Unknown',
                    vuln_count,
                    vuln_list
                ])
        
        print(f"📈 CSV summary saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='SuiteCRM Security Audit Tool')
    parser.add_argument('--url', help='Single URL to audit')
    parser.add_argument('--file', help='File containing URLs to audit (one per line)')
    parser.add_argument('--ssl-verify', action='store_true', help='Enable SSL verification')
    parser.add_argument('--workers', type=int, default=10, help='Number of parallel workers')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--output', default='suitecrm_audit_report.json', help='Output file for detailed report')
    parser.add_argument('--csv', default='suitecrm_audit_summary.csv', help='Output file for CSV summary')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        print("❌ Please provide either --url or --file argument")
        parser.print_help()
        return
    
    # Initialize auditor
    auditor = SuiteCRMAuditor(
        ssl_verify=args.ssl_verify,
        max_workers=args.workers,
        timeout=args.timeout
    )
    
    # Get URLs to audit
    if args.url:
        urls = [args.url]
    else:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    
    # Perform audit
    results = auditor.audit_batch(urls)
    
    # Generate reports
    report = auditor.generate_report(results, args.output)
    auditor.generate_csv_summary(results, args.csv)
    
    # Print summary
    print(f"\n📊 AUDIT SUMMARY")
    print(f"   Total targets: {report['total_targets']}")
    print(f"   Successful scans: {report['successful_scans']}")
    print(f"   Failed scans: {report['failed_scans']}")
    print(f"   Total vulnerabilities found: {report['total_vulnerabilities']}")
    
    # Show high-risk findings
    high_risk = [r for r in results if len(r['vulnerabilities']) > 0]
    if high_risk:
        print(f"\n🚨 HIGH-RISK TARGETS:")
        for result in high_risk:
            print(f"   {result['url']} - {len(result['vulnerabilities'])} vulnerabilities")

if __name__ == "__main__":
    main()
