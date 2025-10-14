import { logEvent, trackFailedLogin, logSuccessfulLogin, logSecurityEvent } from "./logger.js";

console.log("Testing Winston logger...");

// Test basic logging
logEvent('info', 'Test info message', { test: true });
logEvent('warn', 'Test warning message', { test: true });
logEvent('error', 'Test error message', { test: true });

// Test security events
logSecurityEvent('test_event', 'Test security event', { test: true });

// Test failed login tracking
console.log("Testing failed login tracking...");
for (let i = 0; i < 6; i++) {
  const isLocked = trackFailedLogin('testuser', '192.168.1.100', 'TestAgent/1.0');
  console.log(`Attempt ${i + 1}: Account locked = ${isLocked}`);
}

// Test successful login
logSuccessfulLogin('testuser', '192.168.1.100', 'TestAgent/1.0');

console.log("Logger test completed. Check logs directory for output files.");