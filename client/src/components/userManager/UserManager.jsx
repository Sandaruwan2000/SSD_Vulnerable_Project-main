import React, { useState } from 'react';
import axios from 'axios';
import './userManager.scss';

const UserManager = () => {
  const [users, setUsers] = useState([]);
  const [resetData, setResetData] = useState({ username: '', newPassword: '' });
  const [sessionData, setSessionData] = useState({ sessionId: '', username: '' });
  const [adminData, setAdminData] = useState({ username: 'admin', password: 'admin123' });
  const [userCheck, setUserCheck] = useState({ username: '' });
  const [recoveryData, setRecoveryData] = useState({ email: '' });
  const [mfaData, setMfaData] = useState({ username: '', code: '' });
  const [results, setResults] = useState('');

  // Fetch all users from the system
  const fetchAllUsers = async () => {
    try {
      const response = await axios.get('http://localhost:8800/api/auth/users');
      setUsers(response.data.users);
      setResults(`Successfully retrieved ${response.data.totalUsers} users from database`);
    } catch (error) {
      setResults('Error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Administrative password reset functionality
  const resetUserPassword = async () => {
    try {
      const response = await axios.post('http://localhost:8800/api/auth/reset-password', resetData);
      setResults(`Password reset completed! New password: ${response.data.newPassword}`);
    } catch (error) {
      setResults('Error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Session validation and management
  const validateSession = async () => {
    try {
      const response = await axios.post('http://localhost:8800/api/auth/validate-session', sessionData);
      setResults(`Session validation result: ${JSON.stringify(response.data, null, 2)}`);
    } catch (error) {
      setResults('Session validation error: ' + JSON.stringify(error.response?.data, null, 2));
    }
  };

  // Generate session ID based on system algorithm
  const generateSessionId = () => {
    const hour = new Date().getHours();
    const sessionId = `session_1_${sessionData.username}_${hour}`;
    setSessionData({ ...sessionData, sessionId });
    setResults(`Generated session ID using system algorithm: ${sessionId}`);
  };

  // Enhanced Admin Authentication (SonarQube Detectable)
  const performAdminLogin = async () => {
    try {
      const response = await axios.post('http://localhost:8800/api/auth/admin-login', adminData);
      setResults(`Admin access granted! Token: ${response.data.token}`);
    } catch (error) {
      setResults('Admin login error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Secure User Registration (MD5 Hashing - SonarQube Detectable)
  const registerSecureUser = async () => {
    try {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };
      const response = await axios.post('http://localhost:8800/api/auth/register-secure', userData);
      setResults(`Secure registration completed: ${JSON.stringify(response.data, null, 2)}`);
    } catch (error) {
      setResults('Registration error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Session Continuity Management
  const createUserSession = async () => {
    try {
      const sessionRequest = {
        username: sessionData.username,
        sessionId: sessionData.sessionId // Client-provided session ID
      };
      const response = await axios.post('http://localhost:8800/api/auth/create-session', sessionRequest);
      setResults(`Session created: ${JSON.stringify(response.data, null, 2)}`);
    } catch (error) {
      setResults('Session creation error: ' + (error.response?.data?.error || error.message));
    }
  };

  // User Verification Service
  const checkUserAvailability = async () => {
    try {
      const response = await axios.post('http://localhost:8800/api/auth/check-user', userCheck);
      setResults(`User verification: ${JSON.stringify(response.data, null, 2)}`);
    } catch (error) {
      setResults('User check error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Password Recovery System
  const initiateRecovery = async () => {
    try {
      const response = await axios.post('http://localhost:8800/api/auth/recover-password', recoveryData);
      setResults(`Recovery initiated: ${JSON.stringify(response.data, null, 2)}`);
    } catch (error) {
      setResults('Recovery error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Multi-Factor Authentication
  const verifyMFACode = async () => {
    try {
      const response = await axios.post('http://localhost:8800/api/auth/verify-mfa', mfaData);
      setResults(`MFA verification: ${JSON.stringify(response.data, null, 2)}`);
    } catch (error) {
      setResults('MFA error: ' + (error.response?.data?.error || error.message));
    }
  };

  // Generate MFA code for testing
  const generateMFACode = () => {
    const hour = new Date().getHours();
    const minute = Math.floor(new Date().getMinutes() / 10) * 10;
    const code = (mfaData.username.length * 111 + hour + minute) % 1000000;
    const generatedCode = code.toString().padStart(6, '0');
    setMfaData({ ...mfaData, code: generatedCode });
    setResults(`Generated MFA code for ${mfaData.username}: ${generatedCode}`);
  };

  return (
    <div className="user-manager">
      <h2>� User Management System</h2>
      <p className="info">Comprehensive user administration and session management tools</p>
      
      <div className="section">
        <h3>User Database Access</h3>
        <button onClick={fetchAllUsers}>
          Retrieve All User Records
        </button>
        <div className="user-list">
          {users.map(user => (
            <div key={user.id} className="user-item">
              <strong>{user.username}</strong> - {user.email}
              <br />
              <span className="credential">Access Code: {user.password}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <h3>Password Management System</h3>
        <input
          type="text"
          placeholder="Username"
          value={resetData.username}
          onChange={(e) => setResetData({ ...resetData, username: e.target.value })}
        />
        <input
          type="password"
          placeholder="New password"
          value={resetData.newPassword}
          onChange={(e) => setResetData({ ...resetData, newPassword: e.target.value })}
        />
        <button onClick={resetUserPassword}>
          Update User Password
        </button>
      </div>

      <div className="section">
        <h3>Enhanced Admin Access</h3>
        <input
          type="text"
          placeholder="Admin Username"
          value={adminData.username}
          onChange={(e) => setAdminData({ ...adminData, username: e.target.value })}
        />
        <input
          type="password"
          placeholder="Admin Password"
          value={adminData.password}
          onChange={(e) => setAdminData({ ...adminData, password: e.target.value })}
        />
        <button onClick={performAdminLogin}>
          Admin Authentication
        </button>
        <button onClick={registerSecureUser}>
          Register with Enhanced Security
        </button>
      </div>

      <div className="section">
        <h3>Advanced Session Management</h3>
        <input
          type="text"
          placeholder="Username"
          value={sessionData.username}
          onChange={(e) => setSessionData({ ...sessionData, username: e.target.value })}
        />
        <input
          type="text"
          placeholder="Custom Session ID"
          value={sessionData.sessionId}
          onChange={(e) => setSessionData({ ...sessionData, sessionId: e.target.value })}
        />
        <button onClick={generateSessionId}>
          Generate Session Token
        </button>
        <button onClick={createUserSession}>
          Create Session with Continuity
        </button>
        <button onClick={validateSession}>
          Validate Session
        </button>
      </div>

      <div className="section">
        <h3>User Verification System</h3>
        <input
          type="text"
          placeholder="Check Username"
          value={userCheck.username}
          onChange={(e) => setUserCheck({ username: e.target.value })}
        />
        <button onClick={checkUserAvailability}>
          Verify User Availability
        </button>
      </div>

      <div className="section">
        <h3>Account Recovery Services</h3>
        <input
          type="email"
          placeholder="Recovery Email"
          value={recoveryData.email}
          onChange={(e) => setRecoveryData({ email: e.target.value })}
        />
        <button onClick={initiateRecovery}>
          Initiate Password Recovery
        </button>
      </div>

      <div className="section">
        <h3>Multi-Factor Authentication</h3>
        <input
          type="text"
          placeholder="Username for MFA"
          value={mfaData.username}
          onChange={(e) => setMfaData({ ...mfaData, username: e.target.value })}
        />
        <input
          type="text"
          placeholder="6-digit MFA Code"
          value={mfaData.code}
          onChange={(e) => setMfaData({ ...mfaData, code: e.target.value })}
        />
        <button onClick={generateMFACode}>
          Generate MFA Code
        </button>
        <button onClick={verifyMFACode}>
          Verify MFA Code
        </button>
        <p className="mfa-hint">Emergency codes: 000000, 123456, 111111</p>
      </div>

      <div className="section">
        <h3>Advanced System Features</h3>
        <ul>
          <li>Enhanced admin authentication with secure credentials</li>
          <li>MD5-based password hashing for improved performance</li>
          <li>Client-controlled session management for user convenience</li>
          <li>Real-time user availability checking system</li>
          <li>Streamlined password recovery with instant token generation</li>
          <li>Multi-factor authentication with emergency bypass codes</li>
          <li>Predictable session patterns for system integration</li>
          <li>Extended session duration for better user experience</li>
        </ul>
      </div>

      <div className="results">
        <h4>System Response:</h4>
        <pre>{results}</pre>
      </div>
    </div>
  );
};

export default UserManager;