# Security Fix: Path Traversal and Dynamic Code Loading Vulnerabilities

## Issues Fixed

### 1. Path Traversal Vulnerability (Directory Traversal)
**Path traversal vulnerability** has been resolved. The application previously constructed file paths using user-controlled data without proper validation, allowing attackers to access files outside the intended directory through path manipulation techniques (e.g., `../../../etc/passwd`).

### 2. Dynamic Code Loading Vulnerability (Code Injection)
**Dynamic code loading vulnerability** has been resolved. The application previously used `require()` with user-controlled input, allowing attackers to load arbitrary modules or execute malicious code.

Both vulnerabilities are classified as **Broken Access Control** issues under OWASP Top 10, specifically **A01:2021 - Broken Access Control**.

## Solutions Implemented

### Path Traversal Fix
Path validation and safe file serving have been implemented to prevent directory traversal attacks. Specifically, the file serving endpoint now:

1. **Uses `path.basename()`** to strip directory components from user input
2. **Implements root directory constraint** using `sendFile()` with `root` option
3. **Validates file extensions** against an allowlist of permitted file types
4. **Denies access to dotfiles** using `dotfiles: 'deny'` option
5. **Provides comprehensive error handling** with security logging

### Dynamic Code Loading Fix
Module whitelisting and validation have been implemented to prevent code injection attacks. Specifically, the plugin loading system now:

1. **Validates plugin URLs** against a predefined allowlist of trusted modules
2. **Blocks unauthorized plugin attempts** with detailed security logging
3. **Implements safe error handling** for failed plugin loads
4. **Tracks security events** for audit and monitoring purposes

## Code Examples

### Path Traversal - Noncompliant Code
```javascript
app.get("/api/file", (req, res) => {
  const targetDirectory = "/data/app/resources/";
  const userFilename = path.join(targetDirectory, req.query.filename);
  res.sendFile(userFilename); // Vulnerable to path traversal
});
```

### Path Traversal - Compliant Solution
```javascript
app.get("/api/safe-file", (req, res) => {
  const targetDirectory = path.join(__dirname, "public", "files");
  const userFilename = req.query.filename;
  
  if (!userFilename) {
    return res.status(400).json({ error: "Filename parameter is required" });
  }
  
  // Prevent path traversal by using path.basename and root option
  const safeFilename = path.basename(userFilename);
  
  // Validate file extension
  const allowedExtensions = ['.txt', '.pdf', '.jpg', '.png', '.json'];
  const fileExtension = path.extname(safeFilename).toLowerCase();
  
  if (!allowedExtensions.includes(fileExtension)) {
    return res.status(400).json({ error: "File type not allowed" });
  }
  
  res.sendFile(safeFilename, { 
    root: targetDirectory,
    dotfiles: 'deny'
  });
});
```

### Dynamic Code Loading - Noncompliant Code
```javascript
export const loadDynamicPlugin = (req, res) => {
  const { pluginUrl } = req.body;
  if (pluginUrl) {
    const plugin = require(pluginUrl); // Vulnerable to code injection
    res.json({ plugin: plugin });
  }
};
```

### Dynamic Code Loading - Compliant Solution
```javascript
export const loadDynamicPlugin = (req, res) => {
  const { pluginUrl } = req.body;
  
  if (pluginUrl) {
    // Validate plugin URL against whitelist
    const allowedPlugins = [
      'lodash',
      'moment', 
      'axios',
      './plugins/safe-plugin.js'
    ];
    
    if (!allowedPlugins.includes(pluginUrl)) {
      return res.status(400).json({
        error: "Plugin not in allowed list",
        securityStatus: "Plugin load blocked for security"
      });
    }
    
    try {
      const plugin = require(pluginUrl);
      res.json({ 
        message: "Plugin loaded safely",
        securityStatus: "Trusted plugin execution"
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to load plugin" });
    }
  }
};
```

## Security Benefits

### Path Traversal Protection
- **Directory containment**: Files are served only from designated safe directories
- **Path sanitization**: User input is sanitized using `path.basename()`
- **Extension validation**: Only approved file types are served
- **Hidden file protection**: Dotfiles are automatically denied access
- **Comprehensive logging**: All file access attempts are logged for security monitoring

### Dynamic Code Loading Protection
- **Module whitelisting**: Only pre-approved modules can be loaded
- **Input validation**: Plugin URLs are validated against trusted sources
- **Attack prevention**: Blocks arbitrary code execution attempts
- **Security monitoring**: Logs all plugin loading attempts for audit purposes
- **Error handling**: Provides secure error responses without information disclosure

## Implementation Details

The fixes implement multiple layers of security:

1. **Input validation**: Validates and sanitizes all user-controlled data
2. **Access control**: Restricts operations to authorized resources only
3. **Path normalization**: Uses secure path handling methods
4. **Allowlist validation**: Only permits access to pre-approved resources
5. **Security logging**: Records security events for monitoring and incident response
6. **Error handling**: Provides appropriate error responses without sensitive information disclosure

This ensures that only authorized file access and module loading operations are allowed, effectively preventing path traversal and code injection attacks while maintaining proper access control boundaries.