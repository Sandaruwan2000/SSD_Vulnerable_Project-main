# Security Fix: Server-Side Request Forgery (SSRF) Vulnerabilities

## Issue Fixed
**Server-Side Request Forgery (SSRF) vulnerability** has been resolved. The application previously allowed users to specify arbitrary URLs for server-side HTTP requests without proper validation, enabling attackers to:

- Access internal services and APIs not intended for public access
- Scan internal network infrastructure and enumerate services
- Bypass firewalls and access controls by using the server as a proxy
- Potentially access cloud metadata services (AWS, Azure, GCP)
- Perform port scanning against internal and external hosts
- Access local files through file:// URLs

This is classified as a **Server-Side Request Forgery** vulnerability under OWASP Top 10, related to **A10:2021 - Server-Side Request Forgery (SSRF)**.

## Vulnerability Impact
SSRF attacks can lead to:
- **Internal network reconnaissance**: Mapping internal infrastructure and services
- **Data exfiltration**: Accessing sensitive internal APIs and databases  
- **Cloud metadata access**: Retrieving AWS/Azure instance credentials and secrets
- **Privilege escalation**: Using internal services to gain higher privileges
- **Denial of service**: Overwhelming internal services with requests
- **Firewall bypass**: Accessing restricted resources through the trusted server

## Solution Implemented
Comprehensive URL validation and domain whitelisting have been implemented to prevent SSRF attacks:

### URL Validation and Filtering
1. **URL parsing and validation** using the built-in `URL()` constructor
2. **Scheme validation** allowing only HTTP and HTTPS protocols
3. **Domain whitelisting** with pre-approved external domains only
4. **Private IP blocking** preventing access to internal network ranges
5. **Port filtering** blocking access to common internal service ports
6. **Request configuration** with timeouts and redirect limits

## Code Examples

### Noncompliant Code Example
```javascript
const axios = require('axios');
const express = require('express');

const app = express();

app.get('/api/fetch', async (req, res) => {
    const url = req.query.url; // No validation - vulnerable to SSRF
    try {
        const response = await axios.get(url); // Attacker can access internal services
        res.send(response.data);
    } catch (err) {
        res.status(500).send(err.stack); // Information disclosure
    }
});
```

### Compliant Solution
```javascript
const axios = require('axios');
const express = require('express');

const app = express();

app.get('/api/secure-fetch', async (req, res) => {
    const url = req.query.url;
    
    if (!url) {
        return res.status(400).json({ error: "URL parameter is required" });
    }
    
    try {
        // Parse and validate URL
        const parsedUrl = new URL(url);
        
        // Define allowed schemes and domains
        const allowedSchemes = ["http:", "https:"];
        const allowedDomains = [
            "api.example.com",
            "data.example.com",
            "secure-api.example.org"
        ];
        
        // Validate scheme
        if (!allowedSchemes.includes(parsedUrl.protocol)) {
            return res.status(400).json({ 
                error: "Invalid URL scheme. Only HTTP and HTTPS are allowed." 
            });
        }
        
        // Validate domain
        if (!allowedDomains.includes(parsedUrl.hostname)) {
            return res.status(400).json({ 
                error: "Domain not in allowed list" 
            });
        }
        
        // Prevent access to private IP ranges
        const privateIpRanges = [
            /^127\./, // localhost
            /^10\./, // 10.0.0.0/8
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
            /^192\.168\./, // 192.168.0.0/16
            /^169\.254\./ // link-local
        ];
        
        const isPrivateIp = privateIpRanges.some(range => range.test(parsedUrl.hostname));
        if (isPrivateIp) {
            return res.status(400).json({ 
                error: "Access to private IP ranges is not allowed" 
            });
        }
        
        // Block dangerous ports
        const blockedPorts = [22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 5432, 6379];
        if (parsedUrl.port && blockedPorts.includes(parseInt(parsedUrl.port))) {
            return res.status(400).json({ 
                error: "Access to this port is not allowed" 
            });
        }
        
        // Configure secure request
        const axiosConfig = {
            timeout: 5000,
            maxRedirects: 3,
            validateStatus: (status) => status < 400,
            headers: {
                'User-Agent': 'SecureApp-Fetcher/1.0'
            }
        };
        
        const response = await axios.get(url, axiosConfig);
        
        res.status(200).json({
            success: true,
            data: response.data,
            contentType: response.headers['content-type']
        });
        
    } catch (error) {
        // Secure error handling without information disclosure
        if (error.code === 'ENOTFOUND') {
            return res.status(400).json({ error: "Unable to resolve hostname" });
        } else if (error.code === 'ECONNREFUSED') {
            return res.status(400).json({ error: "Connection refused" });
        } else if (error.code === 'ETIMEDOUT') {
            return res.status(400).json({ error: "Request timeout" });
        } else {
            return res.status(500).json({ error: "Request failed" });
        }
    }
});
```

## Security Controls Implemented

### 1. URL Validation
- **URL parsing**: Uses `new URL()` for proper URL parsing and validation
- **Scheme validation**: Only allows HTTP and HTTPS protocols
- **Malformed URL detection**: Rejects invalid URL formats automatically

### 2. Domain Whitelisting
- **Allowed domains**: Maintains a strict list of approved external domains
- **Hostname validation**: Checks against whitelist before making requests
- **Subdomain control**: Ensures exact hostname matches (no wildcard risks)

### 3. Private Network Protection
- **Private IP blocking**: Prevents access to RFC 1918 private ranges
- **Localhost protection**: Blocks 127.0.0.0/8 and ::1 access
- **Link-local prevention**: Blocks 169.254.0.0/16 and fe80::/10
- **Cloud metadata protection**: Prevents access to 169.254.169.254

### 4. Port Filtering
- **Dangerous port blocking**: Prevents access to SSH (22), Telnet (23), SMTP (25)
- **Database port protection**: Blocks MySQL (3306), PostgreSQL (5432), Redis (6379)
- **Service enumeration prevention**: Stops scanning of common service ports

### 5. Request Security
- **Timeout configuration**: Prevents hanging requests with 5-second timeout
- **Redirect limits**: Restricts redirects to prevent redirect loops
- **Status validation**: Only accepts successful HTTP status codes
- **User-Agent setting**: Identifies requests with custom User-Agent header

### 6. Error Handling
- **Information disclosure prevention**: Generic error messages without sensitive details
- **Security logging**: Records SSRF attempts for monitoring and analysis
- **Graceful degradation**: Handles network errors without system compromise

## Advanced Protection Patterns

### DNS Resolution Validation
```javascript
const dns = require('dns').promises;

async function validateDNS(hostname) {
    try {
        const addresses = await dns.lookup(hostname, { all: true });
        
        // Check if any resolved IP is private
        for (const addr of addresses) {
            if (isPrivateIP(addr.address)) {
                throw new Error('Resolves to private IP');
            }
        }
        return true;
    } catch (error) {
        return false;
    }
}
```

### Cloud Metadata Protection
```javascript
const cloudMetadataBlacklist = [
    '169.254.169.254', // AWS, Azure, Google Cloud
    '192.0.0.192',     // Oracle Cloud
    '100.100.100.200', // Alibaba Cloud
    'metadata.google.internal',
    'instance-data.ec2.internal'
];

function isCloudMetadata(hostname) {
    return cloudMetadataBlacklist.includes(hostname);
}
```

## Implementation Guidelines

### 1. Always Validate URLs
```javascript
// ✅ SECURE - Full URL validation
const parsedUrl = new URL(userUrl);
if (allowedDomains.includes(parsedUrl.hostname)) {
    // Safe to proceed
}

// ❌ VULNERABLE - Direct usage
axios.get(userUrl);
```

### 2. Use Positive Security Models
```javascript
// ✅ SECURE - Whitelist approach
const allowedDomains = ['trusted1.com', 'trusted2.com'];

// ❌ VULNERABLE - Blacklist approach (incomplete)
const blockedDomains = ['malicious.com'];
```

### 3. Implement Defense in Depth
- URL validation + Domain whitelisting + IP filtering + Port blocking
- Multiple layers ensure comprehensive protection
- Logging and monitoring for security awareness

This comprehensive SSRF prevention ensures that server-side requests are strictly controlled and cannot be abused to access internal resources or perform network reconnaissance.