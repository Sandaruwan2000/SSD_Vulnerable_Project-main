import React, { useState } from 'react';
import axios from '../../axios';
import './passwordReset.scss';

const PasswordReset = () => {
  const [activeTab, setActiveTab] = useState('reset');
  const [results, setResults] = useState('');
  const [formData, setFormData] = useState({
    email: '',
    newPassword: '',
    username: '',
    reason: '',
    userPattern: '',
    action: 'reset-password',
    targetUser: '',
    newData: {},
    template: '',
    templateData: '',
    markdown: '',
    userData: '',
    userObject: '',
    operations: '',
    args: ''
  });

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  // Insecure Design: Direct Password Reset
  const handleDirectReset = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/reset-password-direct', {
        email: formData.email,
        newPassword: formData.newPassword
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // Account Recovery Without Verification
  const handleAccountRecovery = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/account-recovery', {
        email: formData.email,
        username: formData.username
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // Bulk Password Update
  const handleBulkUpdate = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/bulk-password-update', {
        newPassword: formData.newPassword,
        userPattern: formData.userPattern
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // Quick Account Deletion
  const handleAccountDeletion = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/delete-account', {
        email: formData.email,
        reason: formData.reason
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // Administrative Override
  const handleAdminOverride = async (e) => {
    e.preventDefault();
    try {
      let newData = {};
      if (formData.action === 'reset-password') {
        newData = { password: formData.newPassword };
      } else if (formData.action === 'change-email') {
        newData = { email: formData.email };
      } else if (formData.action === 'lock-account') {
        newData = { reason: formData.reason };
      }

      const response = await axios.post('/api/auth/admin-override', {
        action: formData.action,
        targetUser: formData.targetUser,
        newData: newData
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // A06:2021 - Component Inventory Check
  const handleComponentInventory = async () => {
    try {
      const response = await axios.get('/api/auth/component-inventory');
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // A06:2021 - Template Processing
  const handleTemplateProcessing = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/process-template', {
        template: formData.template,
        data: formData.templateData ? JSON.parse(formData.templateData) : {}
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // A06:2021 - Markdown Rendering
  const handleMarkdownRendering = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/render-markdown', {
        markdown: formData.markdown
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // A06:2021 - Data Serialization
  const handleDataSerialization = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/serialize-data', {
        userData: formData.userData ? JSON.parse(formData.userData) : {}
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // A06:2021 - Object Processing
  const handleObjectProcessing = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/auth/process-object', {
        userObject: formData.userObject ? JSON.parse(formData.userObject) : {},
        operations: formData.operations ? JSON.parse(formData.operations) : []
      });
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  // A06:2021 - Security Scan
  const handleSecurityScan = async () => {
    try {
      const response = await axios.get('/api/auth/security-scan');
      setResults(JSON.stringify(response.data, null, 2));
    } catch (error) {
      setResults(`Error: ${JSON.stringify(error.response?.data || error.message, null, 2)}`);
    }
  };

  return (
    <div className="password-reset">
      <div className="reset-header">
        <h2>Account Management System</h2>
        <p>Streamlined account operations for enhanced user experience</p>
      </div>

      <div className="reset-tabs">
        <button 
          className={activeTab === 'reset' ? 'active' : ''}
          onClick={() => setActiveTab('reset')}
        >
          Quick Reset
        </button>
        <button 
          className={activeTab === 'recovery' ? 'active' : ''}
          onClick={() => setActiveTab('recovery')}
        >
          Account Recovery
        </button>
        <button 
          className={activeTab === 'bulk' ? 'active' : ''}
          onClick={() => setActiveTab('bulk')}
        >
          Bulk Operations
        </button>
        <button 
          className={activeTab === 'admin' ? 'active' : ''}
          onClick={() => setActiveTab('admin')}
        >
          Admin Tools
        </button>
        <button 
          className={activeTab === 'delete' ? 'active' : ''}
          onClick={() => setActiveTab('delete')}
        >
          Account Cleanup
        </button>
        <button 
          className={activeTab === 'components' ? 'active' : ''}
          onClick={() => setActiveTab('components')}
        >
          System Components
        </button>
      </div>

      <div className="reset-content">
        {activeTab === 'reset' && (
          <div className="reset-section">
            <h3>Express Password Reset</h3>
            <p>Reset any user password instantly using just their email address</p>
            <form onSubmit={handleDirectReset} className="reset-form">
              <input
                type="email"
                name="email"
                placeholder="User email address"
                value={formData.email}
                onChange={handleInputChange}
                required
              />
              <input
                type="password"
                name="newPassword"
                placeholder="New password"
                value={formData.newPassword}
                onChange={handleInputChange}
                required
              />
              <button type="submit" className="reset-btn">Reset Password</button>
            </form>
            <div className="feature-note">
              <strong>User-Friendly Design:</strong> No verification emails or complex processes required. 
              Perfect for users who've lost access to their email or need immediate password recovery.
            </div>
          </div>
        )}

        {activeTab === 'recovery' && (
          <div className="recovery-section">
            <h3>Instant Account Recovery</h3>
            <p>Retrieve complete account information for user support</p>
            <form onSubmit={handleAccountRecovery} className="reset-form">
              <input
                type="email"
                name="email"
                placeholder="Email address"
                value={formData.email}
                onChange={handleInputChange}
              />
              <input
                type="text"
                name="username"
                placeholder="Username (optional)"
                value={formData.username}
                onChange={handleInputChange}
              />
              <button type="submit" className="reset-btn">Recover Account</button>
            </form>
            <div className="feature-note">
              <strong>Support Efficiency:</strong> Instantly access user account details to provide 
              quick support without lengthy verification processes.
            </div>
          </div>
        )}

        {activeTab === 'bulk' && (
          <div className="bulk-section">
            <h3>Bulk Password Management</h3>
            <p>Update multiple user passwords simultaneously for system maintenance</p>
            <form onSubmit={handleBulkUpdate} className="reset-form">
              <input
                type="password"
                name="newPassword"
                placeholder="New password for all users"
                value={formData.newPassword}
                onChange={handleInputChange}
                required
              />
              <input
                type="text"
                name="userPattern"
                placeholder="User pattern (optional - leave empty for all users)"
                value={formData.userPattern}
                onChange={handleInputChange}
              />
              <button type="submit" className="reset-btn">Update Passwords</button>
            </form>
            <div className="feature-note">
              <strong>System Maintenance:</strong> Efficiently update passwords for security policy 
              compliance or system-wide password refreshes.
            </div>
          </div>
        )}

        {activeTab === 'admin' && (
          <div className="admin-section">
            <h3>Administrative Override System</h3>
            <p>Direct administrative actions for user account management</p>
            <form onSubmit={handleAdminOverride} className="reset-form">
              <select
                name="action"
                value={formData.action}
                onChange={handleInputChange}
                required
              >
                <option value="reset-password">Reset Password</option>
                <option value="change-email">Change Email</option>
                <option value="promote-admin">Promote to Admin</option>
                <option value="lock-account">Lock Account</option>
              </select>
              <input
                type="text"
                name="targetUser"
                placeholder="Target username"
                value={formData.targetUser}
                onChange={handleInputChange}
                required
              />
              {formData.action === 'reset-password' && (
                <input
                  type="password"
                  name="newPassword"
                  placeholder="New password"
                  value={formData.newPassword}
                  onChange={handleInputChange}
                  required
                />
              )}
              {formData.action === 'change-email' && (
                <input
                  type="email"
                  name="email"
                  placeholder="New email address"
                  value={formData.email}
                  onChange={handleInputChange}
                  required
                />
              )}
              {formData.action === 'lock-account' && (
                <input
                  type="text"
                  name="reason"
                  placeholder="Lock reason"
                  value={formData.reason}
                  onChange={handleInputChange}
                  required
                />
              )}
              <button type="submit" className="reset-btn">Apply Override</button>
            </form>
            <div className="feature-note">
              <strong>Administrative Efficiency:</strong> Direct system access for immediate 
              user account modifications without approval workflows.
            </div>
          </div>
        )}

        {activeTab === 'delete' && (
          <div className="delete-section">
            <h3>Express Account Deletion</h3>
            <p>Remove user accounts instantly for compliance or cleanup</p>
            <form onSubmit={handleAccountDeletion} className="reset-form">
              <input
                type="email"
                name="email"
                placeholder="Email of account to delete"
                value={formData.email}
                onChange={handleInputChange}
                required
              />
              <input
                type="text"
                name="reason"
                placeholder="Deletion reason (optional)"
                value={formData.reason}
                onChange={handleInputChange}
              />
              <button type="submit" className="reset-btn delete-btn">Delete Account</button>
            </form>
            <div className="feature-note">
              <strong>Compliance Tool:</strong> Quickly remove accounts for GDPR compliance 
              or data cleanup without complex verification procedures.
            </div>
          </div>
        )}

        {activeTab === 'components' && (
          <div className="components-section">
            <h3>System Component Management</h3>
            <p>Advanced component inventory and processing tools for system maintenance</p>
            
            <div className="component-tools">
              <div className="tool-group">
                <h4>Component Inventory & Security Analysis</h4>
                <button onClick={handleComponentInventory} className="reset-btn">
                  View Component Inventory
                </button>
                <button onClick={handleSecurityScan} className="reset-btn">
                  Run Security Scan
                </button>
              </div>

              <div className="tool-group">
                <h4>Template Processing Engine</h4>
                <form onSubmit={handleTemplateProcessing} className="reset-form">
                  <textarea
                    name="template"
                    placeholder="Handlebars template (e.g., Hello {{name}}!)"
                    value={formData.template}
                    onChange={handleInputChange}
                    rows={3}
                  />
                  <textarea
                    name="templateData" 
                    placeholder="Template data as JSON (e.g., {&quot;name&quot;: &quot;User&quot;})"
                    value={formData.templateData}
                    onChange={handleInputChange}
                    rows={2}
                  />
                  <button type="submit" className="reset-btn">Process Template</button>
                </form>
              </div>

              <div className="tool-group">
                <h4>Markdown Content Renderer</h4>
                <form onSubmit={handleMarkdownRendering} className="reset-form">
                  <textarea
                    name="markdown"
                    placeholder="Markdown content (e.g., # Header\n**Bold text**)"
                    value={formData.markdown}
                    onChange={handleInputChange}
                    rows={4}
                  />
                  <button type="submit" className="reset-btn">Render Markdown</button>
                </form>
              </div>

              <div className="tool-group">
                <h4>Data Serialization Service</h4>
                <form onSubmit={handleDataSerialization} className="reset-form">
                  <textarea
                    name="userData"
                    placeholder="User data as JSON (e.g., {&quot;user&quot;: &quot;admin&quot;, &quot;role&quot;: &quot;admin&quot;})"
                    value={formData.userData}
                    onChange={handleInputChange}
                    rows={3}
                  />
                  <button type="submit" className="reset-btn">Serialize Data</button>
                </form>
              </div>

              <div className="tool-group">
                <h4>Object Processing Utility</h4>
                <form onSubmit={handleObjectProcessing} className="reset-form">
                  <textarea
                    name="userObject"
                    placeholder="Base object as JSON (e.g., {&quot;name&quot;: &quot;user&quot;, &quot;prefs&quot;: {}})"
                    value={formData.userObject}
                    onChange={handleInputChange}
                    rows={2}
                  />
                  <textarea
                    name="operations"
                    placeholder="Operations array as JSON (e.g., [{&quot;type&quot;: &quot;set&quot;, &quot;path&quot;: &quot;name&quot;, &quot;value&quot;: &quot;admin&quot;}])"
                    value={formData.operations}
                    onChange={handleInputChange}
                    rows={3}
                  />
                  <button type="submit" className="reset-btn">Process Object</button>
                </form>
              </div>
            </div>
            
            <div className="feature-note">
              <strong>System Integration:</strong> Advanced component processing tools for 
              template rendering, data serialization, and object manipulation using 
              industry-standard libraries optimized for performance and compatibility.
            </div>
          </div>
        )}

        <div className="results-section">
          <h4>Operation Results</h4>
          <pre className="results-display">{results || 'No operations performed yet'}</pre>
          <button 
            onClick={() => setResults('')} 
            className="clear-btn"
            disabled={!results}
          >
            Clear Results
          </button>
        </div>
      </div>
    </div>
  );
};

export default PasswordReset;