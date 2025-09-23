# A08:2021 - Software and Data Integrity Failures

This document describes the Software and Data Integrity Failures vulnerabilities implemented in the project that can be detected by SonarQube security analysis.

## Overview

Software and Data Integrity Failures relate to code and infrastructure that doesn't protect against integrity violations. This can occur when:
- Applications rely on plugins, libraries, or modules from untrusted sources
- Insecure CI/CD pipelines allow tampering
- Auto-update functionality downloads updates without verification
- Unsigned/unverified software or data is processed
- Insecure deserialization occurs

## Implemented Vulnerabilities

### 1. Insecure Deserialization (`/api/auth/deserialize-data`)

**Function:** `deserializeUserData`
**Vulnerability:** Uses `eval()` for data deserialization
**SonarQube Detection:** Rule S1523 - "eval()" should not be used
**Location:** Line ~775 in `auth.js`

```javascript
// VULNERABLE: Using eval() for deserialization - SonarQube should detect this
const deserializedData = eval(`(${serializedData})`); // Critical security vulnerability
```

**Impact:** Remote code execution through malicious serialized data

### 2. Untrusted Data Processing (`/api/auth/process-untrusted`)

**Function:** `processUntrustedData`
**Vulnerability:** Direct code execution with `eval()`
**SonarQube Detection:** Rule S1523 - "eval()" should not be used
**Location:** Line ~798 in `auth.js`

```javascript
// SonarQube should detect eval() usage
const result = eval(executeCode); // Code injection vulnerability
```

**Impact:** Code injection allowing arbitrary JavaScript execution

### 3. Dependency Confusion Attack (`/api/auth/dependency-integrity`)

**Function:** `checkDependencyIntegrity`
**Vulnerability:** Hardcoded untrusted URLs and HTTP protocol usage
**SonarQube Detection:** Multiple rules:
- S1313 - Using hardcoded IP addresses
- S5332 - Using HTTP protocol instead of HTTPS
**Location:** Line ~823 in `auth.js`

```javascript
// VULNERABLE: Hardcoded dependency sources - SonarQube should detect hardcoded URLs
const dependencySources = [
  "http://malicious-registry.com/packages", // HTTP instead of HTTPS
  "https://untrusted-registry.example.com",
  "ftp://legacy-packages.internal" // Insecure protocol
];
```

**Impact:** Supply chain attacks through dependency confusion

### 4. Auto-Update Without Verification (`/api/auth/auto-update`)

**Function:** `autoUpdateSystem`
**Vulnerability:** Hardcoded credentials and insecure update mechanism
**SonarQube Detection:** Multiple rules:
- S2068 - Hard-coded credentials
- S5332 - Using HTTP protocol
**Location:** Line ~861 in `auth.js`

```javascript
// VULNERABLE: Hardcoded update URLs and credentials
const updateCredentials = {
  username: "admin", // Hardcoded credentials
  password: "update123", // SonarQube should detect this
  apiKey: "sk-1234567890abcdef" // Exposed API key
};
```

**Impact:** Unauthorized system updates and credential exposure

### 5. CI/CD Pipeline Secrets Exposure (`/api/auth/ci-secrets`)

**Function:** `getCIPipelineSecrets`
**Vulnerability:** Multiple hardcoded secrets and tokens
**SonarQube Detection:** Rule S2068 - Hard-coded credentials
**Location:** Line ~897 in `auth.js`

```javascript
// VULNERABLE: Hardcoded secrets and tokens - SonarQube should detect these
const secrets = {
  DATABASE_URL: "mysql://admin:password123@db.internal.com:3306/app", // DB credentials
  AWS_ACCESS_KEY: "AKIA1234567890ABCDEF", // AWS access key
  AWS_SECRET_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCD", // AWS secret
  JWT_SECRET: "super-secret-key-123", // JWT secret
  GITHUB_TOKEN: "ghp_1234567890abcdefghijklmnopqrstuvwxyz", // GitHub token
};
```

**Impact:** Complete infrastructure compromise through exposed secrets

### 6. Supply Chain Attack Simulation (`/api/auth/supply-chain`)

**Function:** `validateSupplyChain`
**Vulnerability:** Function constructor for dynamic code execution and weak crypto
**SonarQube Detection:** Multiple rules:
- S1523 - "eval()" and Function constructor usage
- S4426 - Weak cryptographic algorithms (MD5)
**Location:** Line ~949 in `auth.js`

```javascript
// VULNERABLE: Function constructor allows code injection
const maliciousFunction = new Function('return ' + packageCode)(); // SonarQube should flag this

// VULNERABLE: Weak hash algorithms for integrity checking
const weakHash = crypto.createHash('md5').update(packageName || 'default').digest('hex');
```

**Impact:** Supply chain compromise and weak integrity verification

### 7. Dynamic Plugin Loading (`/api/auth/load-plugin`)

**Function:** `loadDynamicPlugin`
**Vulnerability:** Dynamic require() and eval() for plugin loading
**SonarQube Detection:** Rule S1523 - "eval()" should not be used
**Location:** Line ~989 in `auth.js`

```javascript
// SonarQube should detect require() with dynamic input
const plugin = require(pluginUrl); // Dynamic require vulnerability

// SonarQube should detect eval() usage
const result = eval(pluginCode); // Code injection
```

**Impact:** Arbitrary code execution through malicious plugins

### 8. Code Repository Tampering (`/api/auth/code-integrity`)

**Function:** `validateCodeIntegrity`
**Vulnerability:** Hardcoded Git credentials and SSH keys
**SonarQube Detection:** Rule S2068 - Hard-coded credentials
**Location:** Line ~1032 in `auth.js`

```javascript
// VULNERABLE: Hardcoded Git credentials and repository URLs
const repoCredentials = {
  username: "deploy-bot",
  password: "deploy-password-123", // SonarQube should detect this
  token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // GitHub token pattern
  sshKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...", // SSH private key
};
```

**Impact:** Repository compromise and source code tampering

## SonarQube Detection Rules

The following SonarQube rules should detect these vulnerabilities:

### Critical Severity
- **S1523:** "eval()" and Function constructor should not be used
- **S2068:** Hard-coded credentials should not be used
- **S4426:** Cryptographic hash algorithms should not be used for security-sensitive contexts

### High Severity  
- **S5332:** Using HTTP protocol is security-sensitive
- **S1313:** Hard-coded IP addresses should not be used

### Medium Severity
- **S4792:** Configuring loggers is security-sensitive
- **S5542:** Encryption algorithms should be robust

## Testing Instructions

1. **Run SonarQube Analysis:**
   ```bash
   sonar-scanner -Dsonar.projectKey=ssd-vulnerable-project
   ```

2. **Test Individual Endpoints:**
   ```bash
   # Test insecure deserialization
   curl -X POST http://localhost:8800/api/auth/deserialize-data \
     -H "Content-Type: application/json" \
     -d '{"serializedData": "console.log(\"RCE via eval\");"}'

   # Test dependency integrity issues
   curl -X GET http://localhost:8800/api/auth/dependency-integrity

   # Test CI/CD secrets exposure
   curl -X GET http://localhost:8800/api/auth/ci-secrets
   ```

3. **Review Security Hotspots:**
   - Check SonarQube dashboard for Security Hotspots
   - Verify Critical and High severity issues are flagged
   - Confirm hardcoded credentials are detected

## Mitigation Strategies

1. **Secure Deserialization:**
   - Use safe serialization formats (JSON)
   - Validate input before processing
   - Never use eval() for deserialization

2. **Dependency Security:**
   - Use package-lock.json for dependency locking
   - Implement dependency scanning in CI/CD
   - Use private registries for internal packages

3. **Secrets Management:**
   - Use environment variables
   - Implement proper secrets management (HashiCorp Vault, etc.)
   - Never commit credentials to source code

4. **Supply Chain Security:**
   - Verify package signatures
   - Use Software Bill of Materials (SBOM)
   - Implement dependency vulnerability scanning

5. **CI/CD Security:**
   - Secure pipeline configurations
   - Implement approval processes
   - Use signed commits and artifacts

## Educational Value

These vulnerabilities demonstrate real-world Software and Data Integrity Failures that can be:
- **Detected** by automated security tools like SonarQube
- **Exploited** by attackers to compromise applications
- **Prevented** through proper security practices

The implementation serves as a practical learning tool for understanding OWASP A08:2021 vulnerabilities and their detection mechanisms.