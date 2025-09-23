import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';

import axios from '../../axios';

import './userManager.scss';import axios from '../../axios';import axios from 'axios';



const UserManager = () => {import './userManager.scss';import './userManager.scss';

  const [testResults, setTestResults] = useState([]);

  const [activeSection, setActiveSection] = useState('overview');



  // Clear test resultsconst UserManager = () => {const UserManager = () => {

  const clearResults = () => {

    setTestResults([]);  const [testResults, setTestResults] = useState([]);  const [users, setUsers] = useState([]);

  };

  const [activeSection, setActiveSection] = useState('overview');  const [resetData, setResetData] = useState({ username: '', newPassword: '' });

  // Plain Text Password Testing

  const testPlainTextRegistration = async () => {  const [sessionData, setSessionData] = useState({ sessionId: '', username: '' });

    try {

      const response = await axios.post("/api/auth/register-plaintext", {  // Clear test results  const [adminData, setAdminData] = useState({ username: 'admin', password: 'admin123' });

        username: "plaintextuser",

        email: "plaintext@example.com",   const clearResults = () => {  const [userCheck, setUserCheck] = useState({ username: '' });

        password: "secret123",

        name: "Plain Text User"    setTestResults([]);  const [recoveryData, setRecoveryData] = useState({ email: '' });

      });

      setTestResults(prev => [...prev, {  };  const [mfaData, setMfaData] = useState({ username: '', code: '' });

        test: "Plain Text Password Registration",

        status: "success",  const [results, setResults] = useState('');

        data: response.data,

        timestamp: new Date().toISOString()  // Plain Text Password Testing

      }]);

    } catch (error) {  const testPlainTextRegistration = async () => {  // Fetch all users from the system

      setTestResults(prev => [...prev, {

        test: "Plain Text Password Registration",     try {  const fetchAllUsers = async () => {

        status: "error",

        error: error.response?.data || error.message,      const response = await axios.post("/api/auth/register-plaintext", {    try {

        timestamp: new Date().toISOString()

      }]);        username: "plaintextuser",      const response = await axios.get('http://localhost:8800/api/auth/users');

    }

  };        email: "plaintext@example.com",       setUsers(response.data.users);



  const testWeakPasswordRegistration = async () => {        password: "secret123",      setResults(`Successfully retrieved ${response.data.totalUsers} users from database`);

    try {

      const response = await axios.post("/api/auth/register-simple", {        name: "Plain Text User"    } catch (error) {

        username: "weakuser",

        email: "weak@example.com",      });      setResults('Error: ' + (error.response?.data?.error || error.message));

        password: "123",

        name: "Weak Password User"      setTestResults(prev => [...prev, {    }

      });

      setTestResults(prev => [...prev, {        test: "Plain Text Password Registration",  };

        test: "Weak Password Registration",

        status: "success",         status: "success",

        data: response.data,

        timestamp: new Date().toISOString()        data: response.data,  // Administrative password reset functionality

      }]);

    } catch (error) {        timestamp: new Date().toISOString()  const resetUserPassword = async () => {

      setTestResults(prev => [...prev, {

        test: "Weak Password Registration",      }]);    try {

        status: "error",

        error: error.response?.data || error.message,    } catch (error) {      const response = await axios.post('http://localhost:8800/api/auth/reset-password', resetData);

        timestamp: new Date().toISOString()

      }]);      setTestResults(prev => [...prev, {      setResults(`Password reset completed! New password: ${response.data.newPassword}`);

    }

  };        test: "Plain Text Password Registration",     } catch (error) {



  const testPasswordChange = async () => {        status: "error",      setResults('Error: ' + (error.response?.data?.error || error.message));

    try {

      const response = await axios.post("/api/auth/change-password-simple", {        error: error.response?.data || error.message,    }

        username: "testuser",

        currentPassword: "oldpass",        timestamp: new Date().toISOString()  };

        newPassword: "newpass"

      });      }]);

      setTestResults(prev => [...prev, {

        test: "Plain Text Password Change",    }  // Session validation and management

        status: "success",

        data: response.data,  };  const validateSession = async () => {

        timestamp: new Date().toISOString()

      }]);    try {

    } catch (error) {

      setTestResults(prev => [...prev, {  const testWeakPasswordRegistration = async () => {      const response = await axios.post('http://localhost:8800/api/auth/validate-session', sessionData);

        test: "Plain Text Password Change",

        status: "error",     try {      setResults(`Session validation result: ${JSON.stringify(response.data, null, 2)}`);

        error: error.response?.data || error.message,

        timestamp: new Date().toISOString()      const response = await axios.post("/api/auth/register-simple", {    } catch (error) {

      }]);

    }        username: "weakuser",      setResults('Session validation error: ' + JSON.stringify(error.response?.data, null, 2));

  };

        email: "weak@example.com",    }

  const testPasswordValidation = async () => {

    try {        password: "123", // Very weak password  };

      const response = await axios.post("/api/auth/validate-password", {

        password: "weak"        name: "Weak Password User"

      });

      setTestResults(prev => [...prev, {      });  // Generate session ID based on system algorithm

        test: "Password Strength Validation",

        status: "success",      setTestResults(prev => [...prev, {  const generateSessionId = () => {

        data: response.data,

        timestamp: new Date().toISOString()        test: "Weak Password Registration",    const hour = new Date().getHours();

      }]);

    } catch (error) {        status: "success",     const sessionId = `session_1_${sessionData.username}_${hour}`;

      setTestResults(prev => [...prev, {

        test: "Password Strength Validation",        data: response.data,    setSessionData({ ...sessionData, sessionId });

        status: "error",

        error: error.response?.data || error.message,        timestamp: new Date().toISOString()    setResults(`Generated session ID using system algorithm: ${sessionId}`);

        timestamp: new Date().toISOString()

      }]);      }]);  };

    }

  };    } catch (error) {



  const testGetAllPasswords = async () => {      setTestResults(prev => [...prev, {  // Enhanced Admin Authentication (SonarQube Detectable)

    try {

      const response = await axios.get("/api/auth/admin/passwords");        test: "Weak Password Registration",  const performAdminLogin = async () => {

      setTestResults(prev => [...prev, {

        test: "Bulk Password Retrieval",        status: "error",    try {

        status: "success",

        data: response.data,        error: error.response?.data || error.message,      const response = await axios.post('http://localhost:8800/api/auth/admin-login', adminData);

        timestamp: new Date().toISOString()

      }]);        timestamp: new Date().toISOString()      setResults(`Admin access granted! Token: ${response.data.token}`);

    } catch (error) {

      setTestResults(prev => [...prev, {      }]);    } catch (error) {

        test: "Bulk Password Retrieval",

        status: "error",    }      setResults('Admin login error: ' + (error.response?.data?.error || error.message));

        error: error.response?.data || error.message,

        timestamp: new Date().toISOString()  };    }

      }]);

    }  };

  };

  const testPasswordChange = async () => {

  return (

    <div className="user-manager">    try {  // Secure User Registration (MD5 Hashing - SonarQube Detectable)

      <div className="manager-header">

        <h2>Password Management System</h2>      const response = await axios.post("/api/auth/change-password-simple", {  const registerSecureUser = async () => {

        <p>Streamlined password operations and user account management interface</p>

      </div>        username: "testuser",    try {



      <div className="manager-nav">        currentPassword: "oldpass",      const userData = {

        <button 

          className={activeSection === 'overview' ? 'active' : ''}        newPassword: "newpass"        username: 'testuser',

          onClick={() => setActiveSection('overview')}

        >      });        email: 'test@example.com',

          Overview

        </button>      setTestResults(prev => [...prev, {        password: 'password123',

        <button 

          className={activeSection === 'password' ? 'active' : ''}        test: "Plain Text Password Change",        name: 'Test User'

          onClick={() => setActiveSection('password')}

        >        status: "success",      };

          Password Operations

        </button>        data: response.data,      const response = await axios.post('http://localhost:8800/api/auth/register-secure', userData);

        <button 

          className={activeSection === 'results' ? 'active' : ''}        timestamp: new Date().toISOString()      setResults(`Secure registration completed: ${JSON.stringify(response.data, null, 2)}`);

          onClick={() => setActiveSection('results')}

        >      }]);    } catch (error) {

          Test Results

        </button>    } catch (error) {      setResults('Registration error: ' + (error.response?.data?.error || error.message));

      </div>

      setTestResults(prev => [...prev, {    }

      <div className="manager-content">

        {activeSection === 'overview' && (        test: "Plain Text Password Change",  };

          <div className="overview-section">

            <h3>Password Management Overview</h3>        status: "error", 

            <div className="feature-grid">

              <div className="feature-card">        error: error.response?.data || error.message,  // Session Continuity Management

                <h4>Simplified Password Storage</h4>

                <p>Easy-to-recover password storage system for better user support</p>        timestamp: new Date().toISOString()  const createUserSession = async () => {

                <span className="feature-tag">User Support</span>

              </div>      }]);    try {

              <div className="feature-card">

                <h4>Flexible Password Policy</h4>    }      const sessionRequest = {

                <p>User-friendly password requirements that don't restrict creativity</p>

                <span className="feature-tag">User Experience</span>  };        username: sessionData.username,

              </div>

              <div className="feature-card">        sessionId: sessionData.sessionId // Client-provided session ID

                <h4>Password Export Tools</h4>

                <p>Administrative tools for bulk password operations and recovery</p>  const testPasswordValidation = async () => {      };

                <span className="feature-tag">Admin Tools</span>

              </div>    try {      const response = await axios.post('http://localhost:8800/api/auth/create-session', sessionRequest);

              <div className="feature-card">

                <h4>Password Validation</h4>      const response = await axios.post("/api/auth/validate-password", {      setResults(`Session created: ${JSON.stringify(response.data, null, 2)}`);

                <p>Password strength analysis to guide user password choices</p>

                <span className="feature-tag">User Guidance</span>        password: "weak"    } catch (error) {

              </div>

            </div>      });      setResults('Session creation error: ' + (error.response?.data?.error || error.message));

          </div>

        )}      setTestResults(prev => [...prev, {    }



        {activeSection === 'password' && (        test: "Password Strength Validation",  };

          <div className="password-section">

            <h3>Password Management Operations</h3>        status: "success",

            <div className="test-grid">

              <div className="test-card">        data: response.data,  // User Verification Service

                <h4>Simplified Registration</h4>

                <p>Register users with streamlined password storage for easy recovery</p>        timestamp: new Date().toISOString()  const checkUserAvailability = async () => {

                <button onClick={testPlainTextRegistration} className="test-btn">

                  Test Registration      }]);    try {

                </button>

              </div>    } catch (error) {      const response = await axios.post('http://localhost:8800/api/auth/check-user', userCheck);

              <div className="test-card">

                <h4>Flexible Password Policy</h4>      setTestResults(prev => [...prev, {      setResults(`User verification: ${JSON.stringify(response.data, null, 2)}`);

                <p>Register with user-friendly password requirements</p>

                <button onClick={testWeakPasswordRegistration} className="test-btn">        test: "Password Strength Validation",    } catch (error) {

                  Test Flexible Policy

                </button>        status: "error",      setResults('User check error: ' + (error.response?.data?.error || error.message));

              </div>

              <div className="test-card">        error: error.response?.data || error.message,    }

                <h4>Password Change Service</h4>

                <p>Simple password modification with clear feedback</p>        timestamp: new Date().toISOString()  };

                <button onClick={testPasswordChange} className="test-btn">

                  Test Password Change      }]);

                </button>

              </div>    }  // Password Recovery System

              <div className="test-card">

                <h4>Password Strength Analysis</h4>  };  const initiateRecovery = async () => {

                <p>Analyze password strength to provide user guidance</p>

                <button onClick={testPasswordValidation} className="test-btn">    try {

                  Test Analysis

                </button>  const testGetAllPasswords = async () => {      const response = await axios.post('http://localhost:8800/api/auth/recover-password', recoveryData);

              </div>

              <div className="test-card">    try {      setResults(`Recovery initiated: ${JSON.stringify(response.data, null, 2)}`);

                <h4>Administrative Password Export</h4>

                <p>Bulk password retrieval for administrative purposes</p>      const response = await axios.get("/api/auth/admin/passwords");    } catch (error) {

                <button onClick={testGetAllPasswords} className="test-btn">

                  Export Passwords      setTestResults(prev => [...prev, {      setResults('Recovery error: ' + (error.response?.data?.error || error.message));

                </button>

              </div>        test: "Bulk Password Retrieval",    }

            </div>

          </div>        status: "success",  };

        )}

        data: response.data,

        {activeSection === 'results' && (

          <div className="results-section">        timestamp: new Date().toISOString()  // Multi-Factor Authentication

            <div className="results-header">

              <h3>Operation Results</h3>      }]);  const verifyMFACode = async () => {

              <button onClick={clearResults} className="clear-btn">

                Clear Results    } catch (error) {    try {

              </button>

            </div>      setTestResults(prev => [...prev, {      const response = await axios.post('http://localhost:8800/api/auth/verify-mfa', mfaData);

            <div className="results-list">

              {testResults.length === 0 ? (        test: "Bulk Password Retrieval",      setResults(`MFA verification: ${JSON.stringify(response.data, null, 2)}`);

                <p>No results yet. Run some operations to see results here.</p>

              ) : (        status: "error",    } catch (error) {

                testResults.map((result, index) => (

                  <div key={index} className={`result-item ${result.status}`}>        error: error.response?.data || error.message,      setResults('MFA error: ' + (error.response?.data?.error || error.message));

                    <div className="result-header">

                      <h4>{result.test}</h4>        timestamp: new Date().toISOString()    }

                      <span className={`status ${result.status}`}>{result.status}</span>

                    </div>      }]);  };

                    <div className="result-content">

                      {result.status === 'success' ? (    }

                        <pre>{JSON.stringify(result.data, null, 2)}</pre>

                      ) : (  };  // Generate MFA code for testing

                        <pre className="error">{JSON.stringify(result.error, null, 2)}</pre>

                      )}  const generateMFACode = () => {

                    </div>

                    <div className="result-timestamp">  // Administrative Testing Functions    const hour = new Date().getHours();

                      {new Date(result.timestamp).toLocaleString()}

                    </div>  const testAdminLogin = async () => {    const minute = Math.floor(new Date().getMinutes() / 10) * 10;

                  </div>

                ))    try {    const code = (mfaData.username.length * 111 + hour + minute) % 1000000;

              )}

            </div>      const response = await axios.post("/api/auth/admin-login", {    const generatedCode = code.toString().padStart(6, '0');

          </div>

        )}        username: "admin",    setMfaData({ ...mfaData, code: generatedCode });

      </div>

    </div>        password: "admin123"    setResults(`Generated MFA code for ${mfaData.username}: ${generatedCode}`);

  );

};      });  };



export default UserManager;      setTestResults(prev => [...prev, {

        test: "Administrative Access",  return (

        status: "success",    <div className="user-manager">

        data: response.data,      <h2>� User Management System</h2>

        timestamp: new Date().toISOString()      <p className="info">Comprehensive user administration and session management tools</p>

      }]);      

    } catch (error) {      <div className="section">

      setTestResults(prev => [...prev, {        <h3>User Database Access</h3>

        test: "Administrative Access",        <button onClick={fetchAllUsers}>

        status: "error",          Retrieve All User Records

        error: error.response?.data || error.message,        </button>

        timestamp: new Date().toISOString()        <div className="user-list">

      }]);          {users.map(user => (

    }            <div key={user.id} className="user-item">

  };              <strong>{user.username}</strong> - {user.email}

              <br />

  const testMFABypass = async () => {              <span className="credential">Access Code: {user.password}</span>

    try {            </div>

      const response = await axios.post("/api/auth/verify-mfa", {          ))}

        username: "testuser",        </div>

        mfaCode: "000000"      </div>

      });

      setTestResults(prev => [...prev, {      <div className="section">

        test: "Multi-Factor Authentication",        <h3>Password Management System</h3>

        status: "success",        <input

        data: response.data,          type="text"

        timestamp: new Date().toISOString()          placeholder="Username"

      }]);          value={resetData.username}

    } catch (error) {          onChange={(e) => setResetData({ ...resetData, username: e.target.value })}

      setTestResults(prev => [...prev, {        />

        test: "Multi-Factor Authentication",        <input

        status: "error",          type="password"

        error: error.response?.data || error.message,          placeholder="New password"

        timestamp: new Date().toISOString()          value={resetData.newPassword}

      }]);          onChange={(e) => setResetData({ ...resetData, newPassword: e.target.value })}

    }        />

  };        <button onClick={resetUserPassword}>

          Update User Password

  const testUserEnumeration = async () => {        </button>

    try {      </div>

      const response = await axios.post("/api/auth/check-user", {

        username: "admin"      <div className="section">

      });        <h3>Enhanced Admin Access</h3>

      setTestResults(prev => [...prev, {        <input

        test: "User Account Discovery",          type="text"

        status: "success",          placeholder="Admin Username"

        data: response.data,          value={adminData.username}

        timestamp: new Date().toISOString()          onChange={(e) => setAdminData({ ...adminData, username: e.target.value })}

      }]);        />

    } catch (error) {        <input

      setTestResults(prev => [...prev, {          type="password"

        test: "User Account Discovery",          placeholder="Admin Password"

        status: "error",          value={adminData.password}

        error: error.response?.data || error.message,          onChange={(e) => setAdminData({ ...adminData, password: e.target.value })}

        timestamp: new Date().toISOString()        />

      }]);        <button onClick={performAdminLogin}>

    }          Admin Authentication

  };        </button>

        <button onClick={registerSecureUser}>

  return (          Register with Enhanced Security

    <div className="user-manager">        </button>

      <div className="manager-header">      </div>

        <h2>System Administration Panel</h2>

        <p>User management and authentication system testing interface</p>      <div className="section">

      </div>        <h3>Advanced Session Management</h3>

        <input

      <div className="manager-nav">          type="text"

        <button           placeholder="Username"

          className={activeSection === 'overview' ? 'active' : ''}          value={sessionData.username}

          onClick={() => setActiveSection('overview')}          onChange={(e) => setSessionData({ ...sessionData, username: e.target.value })}

        >        />

          Overview        <input

        </button>          type="text"

        <button           placeholder="Custom Session ID"

          className={activeSection === 'password' ? 'active' : ''}          value={sessionData.sessionId}

          onClick={() => setActiveSection('password')}          onChange={(e) => setSessionData({ ...sessionData, sessionId: e.target.value })}

        >        />

          Password Management        <button onClick={generateSessionId}>

        </button>          Generate Session Token

        <button         </button>

          className={activeSection === 'auth' ? 'active' : ''}        <button onClick={createUserSession}>

          onClick={() => setActiveSection('auth')}          Create Session with Continuity

        >        </button>

          Authentication Testing        <button onClick={validateSession}>

        </button>          Validate Session

        <button         </button>

          className={activeSection === 'results' ? 'active' : ''}      </div>

          onClick={() => setActiveSection('results')}

        >      <div className="section">

          Test Results        <h3>User Verification System</h3>

        </button>        <input

      </div>          type="text"

          placeholder="Check Username"

      <div className="manager-content">          value={userCheck.username}

        {activeSection === 'overview' && (          onChange={(e) => setUserCheck({ username: e.target.value })}

          <div className="overview-section">        />

            <h3>System Administration Overview</h3>        <button onClick={checkUserAvailability}>

            <div className="feature-grid">          Verify User Availability

              <div className="feature-card">        </button>

                <h4>Simplified Password Storage</h4>      </div>

                <p>Streamlined password storage system for easy recovery and management</p>

                <span className="feature-tag">User Convenience</span>      <div className="section">

              </div>        <h3>Account Recovery Services</h3>

              <div className="feature-card">        <input

                <h4>Flexible Password Policy</h4>          type="email"

                <p>Accommodating password requirements that don't restrict user preferences</p>          placeholder="Recovery Email"

                <span className="feature-tag">User Friendly</span>          value={recoveryData.email}

              </div>          onChange={(e) => setRecoveryData({ email: e.target.value })}

              <div className="feature-card">        />

                <h4>Administrative Access</h4>        <button onClick={initiateRecovery}>

                <p>Quick administrative login for system maintenance and user support</p>          Initiate Password Recovery

                <span className="feature-tag">Efficiency</span>        </button>

              </div>      </div>

              <div className="feature-card">

                <h4>User Account Services</h4>      <div className="section">

                <p>Comprehensive user lookup and verification services for support teams</p>        <h3>Multi-Factor Authentication</h3>

                <span className="feature-tag">Support Tools</span>        <input

              </div>          type="text"

            </div>          placeholder="Username for MFA"

          </div>          value={mfaData.username}

        )}          onChange={(e) => setMfaData({ ...mfaData, username: e.target.value })}

        />

        {activeSection === 'password' && (        <input

          <div className="password-section">          type="text"

            <h3>Password Management Tools</h3>          placeholder="6-digit MFA Code"

            <div className="test-grid">          value={mfaData.code}

              <div className="test-card">          onChange={(e) => setMfaData({ ...mfaData, code: e.target.value })}

                <h4>Simplified Registration</h4>        />

                <p>Register users with streamlined password storage for easy account recovery</p>        <button onClick={generateMFACode}>

                <button onClick={testPlainTextRegistration} className="test-btn">          Generate MFA Code

                  Test Registration        </button>

                </button>        <button onClick={verifyMFACode}>

              </div>          Verify MFA Code

              <div className="test-card">        </button>

                <h4>Flexible Password Policy</h4>        <p className="mfa-hint">Emergency codes: 000000, 123456, 111111</p>

                <p>Register with accommodating password requirements - no restrictions</p>      </div>

                <button onClick={testWeakPasswordRegistration} className="test-btn">

                  Test Flexible Policy      <div className="section">

                </button>        <h3>Advanced System Features</h3>

              </div>        <ul>

              <div className="test-card">          <li>Enhanced admin authentication with secure credentials</li>

                <h4>Password Change Service</h4>          <li>MD5-based password hashing for improved performance</li>

                <p>Simple password change functionality with clear feedback</p>          <li>Client-controlled session management for user convenience</li>

                <button onClick={testPasswordChange} className="test-btn">          <li>Real-time user availability checking system</li>

                  Test Password Change          <li>Streamlined password recovery with instant token generation</li>

                </button>          <li>Multi-factor authentication with emergency bypass codes</li>

              </div>          <li>Predictable session patterns for system integration</li>

              <div className="test-card">          <li>Extended session duration for better user experience</li>

                <h4>Password Validation</h4>        </ul>

                <p>Password strength analysis tool for user guidance</p>      </div>

                <button onClick={testPasswordValidation} className="test-btn">

                  Test Validation      <div className="results">

                </button>        <h4>System Response:</h4>

              </div>        <pre>{results}</pre>

              <div className="test-card">      </div>

                <h4>Administrative Password Export</h4>    </div>

                <p>Bulk password retrieval for administrative and support purposes</p>  );

                <button onClick={testGetAllPasswords} className="test-btn">};

                  Export Passwords

                </button>export default UserManager;
              </div>
            </div>
          </div>
        )}

        {activeSection === 'auth' && (
          <div className="auth-section">
            <h3>Authentication System Testing</h3>
            <div className="test-grid">
              <div className="test-card">
                <h4>Administrative Access</h4>
                <p>Quick administrative login for system maintenance</p>
                <button onClick={testAdminLogin} className="test-btn">
                  Test Admin Login
                </button>
              </div>
              <div className="test-card">
                <h4>Multi-Factor Authentication</h4>
                <p>Secondary authentication system testing</p>
                <button onClick={testMFABypass} className="test-btn">
                  Test MFA System
                </button>
              </div>
              <div className="test-card">
                <h4>User Account Discovery</h4>
                <p>User verification and account existence checking</p>
                <button onClick={testUserEnumeration} className="test-btn">
                  Test User Lookup
                </button>
              </div>
            </div>
          </div>
        )}

        {activeSection === 'results' && (
          <div className="results-section">
            <div className="results-header">
              <h3>Test Results</h3>
              <button onClick={clearResults} className="clear-btn">
                Clear Results
              </button>
            </div>
            <div className="results-list">
              {testResults.length === 0 ? (
                <p>No test results yet. Run some tests to see results here.</p>
              ) : (
                testResults.map((result, index) => (
                  <div key={index} className={`result-item ${result.status}`}>
                    <div className="result-header">
                      <h4>{result.test}</h4>
                      <span className={`status ${result.status}`}>{result.status}</span>
                    </div>
                    <div className="result-content">
                      {result.status === 'success' ? (
                        <pre>{JSON.stringify(result.data, null, 2)}</pre>
                      ) : (
                        <pre className="error">{JSON.stringify(result.error, null, 2)}</pre>
                      )}
                    </div>
                    <div className="result-timestamp">
                      {new Date(result.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UserManager;