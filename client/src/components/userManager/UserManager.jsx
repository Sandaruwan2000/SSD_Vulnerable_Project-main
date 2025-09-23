import React, { useState } from 'react';
import axios from 'axios';
import './userManager.scss';

const UserManager = () => {
  const [users, setUsers] = useState([]);
  const [resetData, setResetData] = useState({ username: '', newPassword: '' });
  const [sessionData, setSessionData] = useState({ sessionId: '', username: '' });
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
        <h3>Session Management Tools</h3>
        <input
          type="text"
          placeholder="Username"
          value={sessionData.username}
          onChange={(e) => setSessionData({ ...sessionData, username: e.target.value })}
        />
        <input
          type="text"
          placeholder="Session ID"
          value={sessionData.sessionId}
          onChange={(e) => setSessionData({ ...sessionData, sessionId: e.target.value })}
        />
        <button onClick={generateSessionId}>
          Generate Session Token
        </button>
        <button onClick={validateSession}>
          Validate Session
        </button>
      </div>

      <div className="section">
        <h3>System Features</h3>
        <ul>
          <li>Direct database access via /api/auth/users endpoint</li>
          <li>Administrative password reset functionality</li>
          <li>Session token generation with predictable patterns</li>
          <li>Special admin headers: 'x-admin-bypass: true'</li>
          <li>User-Agent bypass: 'AdminBot/1.0' for automatic access</li>
          <li>URL parameter privileges: '?makeAdmin=true'</li>
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