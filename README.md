# SuiteCRM Security Audit Tool v2.0

A comprehensive, production-ready security auditing tool for SuiteCRM instances designed for large-scale security assessments.

## 🚀 Key Improvements Over v1.0

### ✅ **Real CVE Database**
- **Real CVEs**: Uses actual SuiteCRM vulnerabilities from NVD/MITRE
- **Version-specific**: CVEs mapped to specific SuiteCRM versions
- **Up-to-date**: Includes latest CVEs through October 2025
- **Detailed metadata**: CVSS scores, version ranges, auth requirements

### ✅ **Non-Destructive Testing**
- **Safe payloads**: Time-based SQL injection detection instead of DROP TABLE
- **Reflection testing**: XSS detection without executing malicious scripts
- **Information disclosure**: Safe pattern matching for sensitive data
- **No data modification**: All tests are read-only

### ✅ **Production-Scale Ready**
- **Batch processing**: Audit 1000+ servers efficiently
- **Parallel execution**: Configurable worker threads (default: 10)
- **Progress tracking**: Real-time status updates
- **Comprehensive reporting**: JSON + CSV output formats

### ✅ **Robust Error Handling**
- **SSL flexibility**: Handle self-signed certificates gracefully
- **Timeout management**: Configurable request timeouts
- **Retry logic**: Automatic retry for failed requests
- **Graceful degradation**: Continue processing despite individual failures

## 📋 Usage

### Single Target Audit
```bash
python suitecrm_audit_tool.py --url https://suitecrm.example.com --ssl-verify
```

### Batch Audit (Recommended for 1000+ servers)
```bash
python suitecrm_audit_tool.py --file servers.txt --workers 20 --timeout 60
```

### Command Line Options
- `--url`: Single URL to audit
- `--file`: File containing URLs (one per line)
- `--ssl-verify`: Enable SSL certificate verification
- `--workers`: Number of parallel workers (default: 10)
- `--timeout`: Request timeout in seconds (default: 30)
- `--output`: JSON report filename (default: suitecrm_audit_report.json)
- `--csv`: CSV summary filename (default: suitecrm_audit_summary.csv)

## 📊 Output Reports

### JSON Report (`suitecrm_audit_report.json`)
```json
{
  "timestamp": "2025-10-XX...",
  "total_targets": 1000,
  "successful_scans": 950,
  "failed_scans": 50,
  "total_vulnerabilities": 234,
  "results": [
    {
      "url": "https://suitecrm.example.com",
      "version_info": "SuiteCRM Version: 8.5.1",
      "detected_version": "8.5.1",
      "matching_version": "8.5.1",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2024-36408",
          "endpoint": "/index.php?module=Alerts&action=index",
          "payload_type": "sql_injection",
          "payload": "' OR SLEEP(5)--",
          "result": "Time-based SQL injection detected (delay: 5.23s)"
        }
      ],
      "status": "success"
    }
  ]
}
```

### CSV Summary (`suitecrm_audit_summary.csv`)
```csv
URL,Status,Detected Version,Vulnerability Count,Vulnerabilities
https://suitecrm1.example.com,success,8.5.1,2,CVE-2024-36408:sql_injection;CVE-2024-36410:sql_injection
https://suitecrm2.example.com,success,8.9.0,0,
https://suitecrm3.example.com,failed,Unknown,0,
```

## 🔍 Real CVE Coverage

### SuiteCRM 8.x Series
- **8.9.0**: Latest version (most CVEs patched)
- **8.8.1**: Patched version
- **8.8.0**: CVE-2025-54785 (Deserialization), CVE-2025-54786 (Auth Bypass)
- **8.7.1**: CVE-2024-50335 (XSS)
- **8.6.2**: CVE-2024-45392 (Access Control)
- **8.6.1**: CVE-2024-36408, CVE-2024-36410 (SQL Injection)

### SuiteCRM 7.x Series
- **7.14.7**: Latest 7.x (most CVEs patched)
- **7.14.6**: CVE-2025-54783 (XSS), CVE-2025-54784 (Stored XSS), CVE-2025-54787 (Info Disclosure)

## 🛡️ Security Features

### Non-Destructive Testing
- **SQL Injection**: Time-based detection using `SLEEP(5)` instead of destructive queries
- **XSS**: Payload reflection detection without script execution
- **Information Disclosure**: Pattern matching for sensitive data exposure
- **File Upload**: Safe file type validation without actual uploads

### Authentication Handling
- **Unauthenticated tests**: For CVEs that don't require authentication
- **Authenticated tests**: For CVEs requiring login (marked in CVE metadata)
- **Session management**: Proper cookie and session handling

### SSL/TLS Support
- **Self-signed certificates**: Automatic handling for internal networks
- **Certificate verification**: Optional strict SSL verification
- **Mixed environments**: Support for both HTTP and HTTPS targets

## 📈 Performance Optimizations

### Parallel Processing
- **Configurable workers**: Adjust based on target infrastructure
- **Connection pooling**: Reuse connections for efficiency
- **Rate limiting**: Built-in delays to avoid overwhelming targets

### Memory Management
- **Streaming responses**: Process large responses efficiently
- **Result batching**: Write results incrementally
- **Cleanup**: Proper resource cleanup after each target

## 🔧 Configuration

### Environment Variables
```bash
export SUITECRM_AUDIT_WORKERS=20
export SUITECRM_AUDIT_TIMEOUT=60
export SUITECRM_AUDIT_SSL_VERIFY=false
```

### Configuration File (Future Enhancement)
```yaml
# suitecrm_audit_config.yaml
ssl:
  verify: false
  timeout: 30

workers:
  max_workers: 10
  retry_attempts: 3

output:
  json_file: "audit_report.json"
  csv_file: "audit_summary.csv"
  log_level: "INFO"
```

## 🚨 Important Notes

### Legal Compliance
- **Authorized testing only**: Only use on systems you own or have explicit permission to test
- **Documentation**: Keep detailed records of authorization
- **Scope limitations**: Respect defined testing boundaries

### Production Considerations
- **Resource usage**: Monitor CPU and memory usage during large scans
- **Network impact**: Consider bandwidth and target server load
- **Logging**: Enable detailed logging for troubleshooting

### False Positives/Negatives
- **Version detection**: Some custom installations may not be detected
- **CVE matching**: Fuzzy matching may miss some edge cases
- **Network issues**: Firewalls or load balancers may affect results

## 🐛 Troubleshooting

### Common Issues
1. **SSL Errors**: Use `--ssl-verify=false` for self-signed certificates
2. **Timeout Errors**: Increase `--timeout` value for slow networks
3. **Memory Issues**: Reduce `--workers` for large scans
4. **Permission Errors**: Ensure write access for output files

### Debug Mode
```bash
python suitecrm_audit_tool.py --url https://example.com --workers 1 --timeout 60
```

## 📞 Support

For issues, questions, or contributions:
- **Issues**: Report bugs and feature requests
- **Documentation**: Check this README and inline comments
- **Updates**: Monitor for CVE database updates

---

**Version**: 2.0  
**Last Updated**: October 2025  
**Compatibility**: Python 3.7+  
**Dependencies**: requests, urllib3
