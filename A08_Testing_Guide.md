# A08:2021 Software and Data Integrity Failures - Testing Guide

## Testing the New Endpoints

These endpoints demonstrate Software and Data Integrity Failures that can be detected by SonarQube:

### 1. Test Insecure Deserialization
```bash
curl -X POST http://localhost:8800/api/auth/deserialize-data \
  -H "Content-Type: application/json" \
  -d '{"serializedData": "console.log(\"RCE via eval\");"}'
```

### 2. Test Untrusted Data Processing  
```bash
curl -X POST http://localhost:8800/api/auth/process-untrusted \
  -H "Content-Type: application/json" \
  -d '{"userData": {"name": "test"}, "executeCode": "1+1"}'
```

### 3. Test Dependency Integrity Issues
```bash
curl -X GET http://localhost:8800/api/auth/dependency-integrity
```

### 4. Test Auto-Update System
```bash
curl -X POST http://localhost:8800/api/auth/auto-update \
  -H "Content-Type: application/json" \
  -d '{"updateSource": "http://malicious.com", "skipVerification": true}'
```

### 5. Test CI/CD Secrets Exposure
```bash
curl -X GET http://localhost:8800/api/auth/ci-secrets
```

### 6. Test Supply Chain Validation
```bash
curl -X POST http://localhost:8800/api/auth/supply-chain \
  -H "Content-Type: application/json" \
  -d '{"packageName": "evil-package", "packageCode": "console.log(\"malicious code\")"}'
```

### 7. Test Dynamic Plugin Loading
```bash
curl -X POST http://localhost:8800/api/auth/load-plugin \
  -H "Content-Type: application/json" \
  -d '{"pluginCode": "console.log(\"plugin loaded\")"}'
```

### 8. Test Code Integrity Check
```bash
curl -X GET http://localhost:8800/api/auth/code-integrity
```

## SonarQube Analysis

Run SonarQube analysis to detect these vulnerabilities:

1. **Install SonarQube Scanner**
2. **Run Analysis:**
   ```bash
   sonar-scanner -Dsonar.projectKey=ssd-vulnerable-project \
     -Dsonar.sources=. \
     -Dsonar.host.url=http://localhost:9000
   ```
3. **Check Results:** Look for Security Hotspots related to:
   - Hard-coded credentials (Rule S2068)
   - eval() usage (Rule S1523)
   - Weak cryptography (Rule S4426)
   - HTTP protocol usage (Rule S5332)

## Expected SonarQube Detections

The following security issues should be detected:

### Critical Issues
- Multiple hardcoded passwords and API keys
- eval() usage for deserialization
- Function constructor for code execution
- MD5 cryptographic usage

### High Issues  
- HTTP protocol usage instead of HTTPS
- Hardcoded IP addresses and URLs
- Dynamic require() statements

### Security Hotspots
- Database credentials in code
- AWS access keys
- GitHub tokens
- SSH private keys

This implementation provides comprehensive A08:2021 vulnerabilities that demonstrate real-world Software and Data Integrity Failures while being detectable by automated security tools like SonarQube.