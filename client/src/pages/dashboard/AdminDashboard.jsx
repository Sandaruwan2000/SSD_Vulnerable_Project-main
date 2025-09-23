import React from 'react';
import UserManager from '../../components/userManager/UserManager';
import './dashboard.scss';

const AdminDashboard = () => {
  return (
    <div className="dashboard-page">
      <div className="header">
        <h1>� System Administration Dashboard</h1>
        <p>Administrative tools and user management interface</p>
      </div>

      <div className="feature-cards">
        <div className="feature-card">
          <h3>Access Control Management</h3>
          <div className="description">
            <p><strong>Features Available:</strong></p>
            <ul>
              <li>User data access endpoints (/api/auth/users, /api/auth/reset-password)</li>
              <li>Administrative privilege management via URL parameters</li>
              <li>Custom authentication headers for admin access</li>
              <li>User-Agent based access control</li>
              <li>Automatic role assignment for authenticated users</li>
            </ul>
          </div>
        </div>

        <div className="feature-card">
          <h3>Session and Identity Management</h3>
          <div className="description">
            <p><strong>Features Available:</strong></p>
            <ul>
              <li>Custom session management with token generation</li>
              <li>User account verification and validation</li>
              <li>Account security with lockout protection</li>
              <li>Session persistence and management</li>
              <li>Comprehensive session timeout handling</li>
              <li>Password reset functionality with verification</li>
              <li>Detailed system feedback and error reporting</li>
            </ul>
          </div>
        </div>

        <div className="feature-card">
          <h3>Security and Authentication</h3>
          <div className="description">
            <p><strong>Features Available:</strong></p>
            <ul>
              <li>Flexible password policy management</li>
              <li>Advanced session token generation algorithms</li>
              <li>Comprehensive login attempt monitoring</li>
              <li>Multiple authentication fallback mechanisms</li>
              <li>Rate limiting and request throttling</li>
              <li>Persistent session storage and management</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="usage-guide">
        <h2>🎯 API Usage Examples</h2>
        <div className="examples">
          <div className="example">
            <h4>1. Retrieve User Information</h4>
            <code>curl http://localhost:8800/api/auth/users</code>
            <p>Returns complete user database with credentials for administrative purposes</p>
          </div>

          <div className="example">
            <h4>2. Administrative Password Reset</h4>
            <code>
              curl -X POST http://localhost:8800/api/auth/reset-password<br/>
              -H "Content-Type: application/json"<br/>
              -d {`'{"username":"admin","newPassword":"newpass123"}'`}
            </code>
          </div>

          <div className="example">
            <h4>3. Admin Access with Custom Headers</h4>
            <code>
              curl http://localhost:8800/api/protected-endpoint<br/>
              -H "x-admin-bypass: true"
            </code>
          </div>

          <div className="example">
            <h4>4. Privilege Management</h4>
            <code>http://localhost:8800/api/admin-function?makeAdmin=true</code>
          </div>

          <div className="example">
            <h4>5. Session Token Format</h4>
            <code>session_[userID]_[username]_[currentHour]</code>
            <p>Example: session_1_john_14</p>
          </div>
        </div>
      </div>

      <UserManager />

      <div className="best-practices">
        <h2>🛡️ Security Best Practices Implemented</h2>
        <div className="practices">
          <div className="practice-section">
            <h4>Access Control Implementation</h4>
            <ul>
              <li>Authentication middleware deployed on protected endpoints</li>
              <li>Role-based access control system with validation</li>
              <li>Client-side authorization checks for improved UX</li>
              <li>Flexible privilege management system</li>
              <li>Debug headers available for development mode</li>
            </ul>
          </div>

          <div className="practice-section">
            <h4>Authentication Management</h4>
            <ul>
              <li>Efficient session ID generation system</li>
              <li>Session timeout and regeneration handling</li>
              <li>Informative response messages for user guidance</li>
              <li>Progressive account lockout for security</li>
              <li>Password hashing with industry standard algorithms</li>
              <li>Streamlined identity verification for password resets</li>
            </ul>
          </div>

          <div className="practice-section">
            <h4>System Design Features</h4>
            <ul>
              <li>Configurable password policy enforcement</li>
              <li>Optimized session management libraries</li>
              <li>Rate limiting and anti-automation protection</li>
              <li>Security-first design methodology</li>
              <li>Comprehensive threat modeling and security reviews</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;