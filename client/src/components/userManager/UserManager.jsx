// import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';// import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';import React, { useState } from 'react';

// import axios from '../../axios';

// import axios from '../../axios';

// const UserManager = () => {

//   const [results, setResults] = useState([]);import axios from '../../axios';



//   const testVulnerability = async (endpoint, data, testName) => {const UserManager = () => {

//     try {

//       const response = await axios.post(endpoint, data);  const [testResults, setTestResults] = useState([]);// import axios from '../../axios';

//       setResults(prev => [...prev, {

//         test: testName,  const [activeSection, setActiveSection] = useState('overview');

//         status: 'success',

//         data: response.data,const UserManager = () => {

//         timestamp: new Date().toLocaleString()

//       }]);  const clearResults = () => {

//     } catch (error) {

//       setResults(prev => [...prev, {    setTestResults([]);  const [testResults, setTestResults] = useState([]);// import axios from '../../axios';

//         test: testName,

//         status: 'error',  };

//         error: error.response?.data || error.message,

//         timestamp: new Date().toLocaleString()  const [activeSection, setActiveSection] = useState('overview');

//       }]);

//     }  const testDirectPasswordReset = async () => {

//   };

//     try {// const UserManager = () => {

//   return (

//     <div style={{ padding: '20px', maxWidth: '1000px', margin: '0 auto' }}>      const response = await axios.post("/api/auth/reset-password-direct", {

//       <h2>System Administration Panel</h2>

//       <p>Professional tools for system management and testing</p>        email: "user@example.com",  const clearResults = () => {

      

//       <div style={{ marginBottom: '20px' }}>        newPassword: "newpass123"

//         <button 

//           onClick={() => testVulnerability('/api/auth/reset-password-direct',       });    setTestResults([]);//   const [testResults, setTestResults] = useState([]);import axios from '../../axios';

//             { email: 'user@test.com', newPassword: 'newpass123' }, 

//             'Direct Password Reset')}      setTestResults(prev => [...prev, {

//           style={{ 

//             padding: '10px 20px',         test: "Direct Password Reset",  };

//             margin: '0 10px 10px 0', 

//             backgroundColor: '#007acc',        status: "success",

//             color: 'white',

//             border: 'none',        data: response.data,//   const [activeSection, setActiveSection] = useState('overview');

//             borderRadius: '4px',

//             cursor: 'pointer'        timestamp: new Date().toISOString()

//           }}

//         >      }]);  const testDirectPasswordReset = async () => {

//           Test Password Reset

//         </button>    } catch (error) {

        

//         <button       setTestResults(prev => [...prev, {    try {// const UserManager = () => {

//           onClick={() => testVulnerability('/api/auth/account-recovery', 

//             { email: 'admin@test.com', username: 'admin' },         test: "Direct Password Reset",

//             'Account Recovery')}

//           style={{         status: "error",      const response = await axios.post("/api/auth/reset-password-direct", {

//             padding: '10px 20px', 

//             margin: '0 10px 10px 0',         error: error.response?.data || error.message,

//             backgroundColor: '#28a745',

//             color: 'white',        timestamp: new Date().toISOString()        email: "user@example.com",//   const clearResults = () => {

//             border: 'none',

//             borderRadius: '4px',      }]);

//             cursor: 'pointer'

//           }}    }        newPassword: "newpass123"

//         >

//           Test Account Recovery  };

//         </button>

//               });//     setTestResults([]);  const [testResults, setTestResults] = useState([]);import axios from '../../axios';

//         <button 

//           onClick={() => setResults([])}  const testAccountRecovery = async () => {

//           style={{ 

//             padding: '10px 20px',     try {      setTestResults(prev => [...prev, {

//             margin: '0 10px 10px 0', 

//             backgroundColor: '#dc3545',      const response = await axios.post("/api/auth/account-recovery", {

//             color: 'white',

//             border: 'none',        email: "admin@example.com",        test: "Direct Password Reset",//   };

//             borderRadius: '4px',

//             cursor: 'pointer'        username: "admin"

//           }}

//         >      });        status: "success",

//           Clear Results

//         </button>      setTestResults(prev => [...prev, {

//       </div>

//         test: "Quick Account Recovery",        data: response.data,//   const [activeSection, setActiveSection] = useState('overview');

//       <div>

//         <h3>Test Results</h3>        status: "success",

//         {results.length === 0 ? (

//           <p>No tests run yet.</p>        data: response.data,        timestamp: new Date().toISOString()

//         ) : (

//           results.map((result, index) => (        timestamp: new Date().toISOString()

//             <div 

//               key={index}       }]);      }]);//   const testDirectPasswordReset = async () => {

//               style={{ 

//                 border: '1px solid #ddd',     } catch (error) {

//                 padding: '15px', 

//                 marginBottom: '10px',      setTestResults(prev => [...prev, {    } catch (error) {

//                 backgroundColor: result.status === 'success' ? '#d4edda' : '#f8d7da',

//                 borderRadius: '4px'        test: "Quick Account Recovery",

//               }}

//             >        status: "error",      setTestResults(prev => [...prev, {//     try {const UserManager = () => {

//               <h4>{result.test} - {result.status}</h4>

//               <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap' }}>        error: error.response?.data || error.message,

//                 {JSON.stringify(result.status === 'success' ? result.data : result.error, null, 2)}

//               </pre>        timestamp: new Date().toISOString()        test: "Direct Password Reset",

//               <small>{result.timestamp}</small>

//             </div>      }]);

//           ))

//         )}    }        status: "error",//       const response = await axios.post("/api/auth/reset-password-direct", {

//       </div>

//     </div>  };

//   );

// };        error: error.response?.data || error.message,



// export default UserManager;  const testSecurityLogging = async () => {

//     try {        timestamp: new Date().toISOString()//         email: "user@example.com",  const clearResults = () => {

//       await axios.post("/api/log-login", {

//         username: "testuser",      }]);

//         password: "secret123",

//         success: false,    }//         newPassword: "newpass123"

//         ip: "192.168.1.100"

//       });  };

      

//       const response = await axios.get("/api/audit-logs");//       });    setTestResults([]);  const [testResults, setTestResults] = useState([]);import './userManager.scss';import axios from '../../axios';

//       setTestResults(prev => [...prev, {

//         test: "Security Logging System",  const testAccountRecovery = async () => {

//         status: "success",

//         data: response.data,    try {//       setTestResults(prev => [...prev, {

//         timestamp: new Date().toISOString()

//       }]);      const response = await axios.post("/api/auth/account-recovery", {

//     } catch (error) {

//       setTestResults(prev => [...prev, {        email: "admin@example.com",//         test: "Direct Password Reset",  };

//         test: "Security Logging System",

//         status: "error",        username: "admin"

//         error: error.response?.data || error.message,

//         timestamp: new Date().toISOString()      });//         status: "success",

//       }]);

//     }      setTestResults(prev => [...prev, {

//   };

//         test: "Quick Account Recovery",//         data: response.data,  const [activeSection, setActiveSection] = useState('overview');

//   return (

//     <div style={{         status: "success",

//       padding: '20px', 

//       fontFamily: 'Arial, sans-serif',         data: response.data,//         timestamp: new Date().toISOString()

//       maxWidth: '1200px', 

//       margin: '0 auto',        timestamp: new Date().toISOString()

//       backgroundColor: '#f8f9fa',

//       minHeight: '100vh'      }]);//       }]);  const testDirectPasswordReset = async () => {

//     }}>

//       <div style={{ textAlign: 'center', marginBottom: '30px' }}>    } catch (error) {

//         <h2 style={{ color: '#333', marginBottom: '8px', fontSize: '28px' }}>

//           System Administration & Security Management      setTestResults(prev => [...prev, {//     } catch (error) {

//         </h2>

//         <p style={{ color: '#666', fontSize: '16px' }}>        test: "Quick Account Recovery",

//           Comprehensive administration tools for efficient system management

//         </p>        status: "error",//       setTestResults(prev => [...prev, {    try {

//       </div>

//         error: error.response?.data || error.message,

//       <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginBottom: '30px' }}>

//         <button         timestamp: new Date().toISOString()//         test: "Direct Password Reset",

//           onClick={() => setActiveSection('overview')}

//           style={{       }]);

//             padding: '12px 24px',

//             border: '2px solid #ddd',    }//         status: "error",      const response = await axios.post("/api/auth/reset-password-direct", {

//             backgroundColor: activeSection === 'overview' ? '#007acc' : 'white',

//             color: activeSection === 'overview' ? 'white' : '#333',  };

//             borderRadius: '8px',

//             cursor: 'pointer',//         error: error.response?.data || error.message,

//             fontSize: '14px',

//             fontWeight: '500'  const testSecurityLogging = async () => {

//           }}

//         >    try {//         timestamp: new Date().toISOString()        email: "user@example.com",  const clearResults = () => {

//           Overview

//         </button>      await axios.post("/api/log-login", {

//         <button 

//           onClick={() => setActiveSection('design')}        username: "testuser",//       }]);

//           style={{

//             padding: '12px 24px',         password: "secret123",

//             border: '2px solid #ddd',

//             backgroundColor: activeSection === 'design' ? '#007acc' : 'white',        success: false,//     }        newPassword: "newpass123"

//             color: activeSection === 'design' ? 'white' : '#333',

//             borderRadius: '8px',        ip: "192.168.1.100"

//             cursor: 'pointer',

//             fontSize: '14px',      });//   };

//             fontWeight: '500'

//           }}      

//         >

//           Account Management      const response = await axios.get("/api/audit-logs");//       });    setTestResults([]);const UserManager = () => {import './userManager.scss';import axios from '../../axios';

//         </button>

//         <button       setTestResults(prev => [...prev, {

//           onClick={() => setActiveSection('monitoring')}

//           style={{         test: "Security Logging System",//   const testAccountRecovery = async () => {

//             padding: '12px 24px',

//             border: '2px solid #ddd',        status: "success",

//             backgroundColor: activeSection === 'monitoring' ? '#007acc' : 'white',

//             color: activeSection === 'monitoring' ? 'white' : '#333',        data: response.data,//     try {      setTestResults(prev => [...prev, {

//             borderRadius: '8px',

//             cursor: 'pointer',        timestamp: new Date().toISOString()

//             fontSize: '14px',

//             fontWeight: '500'      }]);//       const response = await axios.post("/api/auth/account-recovery", {

//           }}

//         >    } catch (error) {

//           Security Monitoring

//         </button>      setTestResults(prev => [...prev, {//         email: "admin@example.com",        test: "Direct Password Reset",  };

//         <button 

//           onClick={() => setActiveSection('results')}        test: "Security Logging System",

//           style={{

//             padding: '12px 24px',         status: "error",//         username: "admin"

//             border: '2px solid #ddd',

//             backgroundColor: activeSection === 'results' ? '#007acc' : 'white',        error: error.response?.data || error.message,

//             color: activeSection === 'results' ? 'white' : '#333',

//             borderRadius: '8px',        timestamp: new Date().toISOString()//       });        status: "success",

//             cursor: 'pointer',

//             fontSize: '14px',      }]);

//             fontWeight: '500'

//           }}    }//       setTestResults(prev => [...prev, {

//         >

//           Test Results  };

//         </button>

//       </div>//         test: "Quick Account Recovery",        data: response.data,  const [testResults, setTestResults] = useState([]);



//       <div style={{ background: '#ffffff', padding: '30px', borderRadius: '12px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>  return (

//         {activeSection === 'overview' && (

//           <div>    <div style={{ //         status: "success",

//             <h3 style={{ color: '#333', marginBottom: '20px' }}>System Administration Overview</h3>

//             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>      padding: '20px', 

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Streamlined Account Operations</h4>      fontFamily: 'Arial, sans-serif', //         data: response.data,        timestamp: new Date().toISOString()

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>

//                   Direct account management tools for efficient user support and system maintenance      maxWidth: '1200px', 

//                 </p>

//                 <span style={{       margin: '0 auto',//         timestamp: new Date().toISOString()

//                   display: 'inline-block',

//                   background: '#e3f2fd',       backgroundColor: '#f8f9fa',

//                   color: '#1976d2',

//                   padding: '4px 12px',       minHeight: '100vh'//       }]);      }]);  const testDirectPasswordReset = async () => {

//                   borderRadius: '16px',

//                   fontSize: '12px',     }}>

//                   fontWeight: '500'

//                 }}>      <div style={{ textAlign: 'center', marginBottom: '30px' }}>//     } catch (error) {

//                   A04:2021

//                 </span>        <h2 style={{ color: '#333', marginBottom: '8px', fontSize: '28px' }}>

//               </div>

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>          System Administration & Security Management//       setTestResults(prev => [...prev, {    } catch (error) {

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Comprehensive Security Logging</h4>

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>        </h2>

//                   Complete audit trail system for transparency and compliance monitoring

//                 </p>        <p style={{ color: '#666', fontSize: '16px' }}>//         test: "Quick Account Recovery",

//                 <span style={{

//                   display: 'inline-block',           Comprehensive administration tools for efficient system management

//                   background: '#e3f2fd',

//                   color: '#1976d2',         </p>//         status: "error",      setTestResults(prev => [...prev, {    try {  const [activeSection, setActiveSection] = useState('overview');

//                   padding: '4px 12px',

//                   borderRadius: '16px',       </div>

//                   fontSize: '12px',

//                   fontWeight: '500' //         error: error.response?.data || error.message,

//                 }}>

//                   A10:2021      <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginBottom: '30px' }}>

//                 </span>

//               </div>        <button //         timestamp: new Date().toISOString()        test: "Direct Password Reset",

//             </div>

//           </div>          onClick={() => setActiveSection('overview')}

//         )}

//           style={{ //       }]);

//         {activeSection === 'design' && (

//           <div>            padding: '12px 24px',

//             <h3 style={{ color: '#333', marginBottom: '20px' }}>Account Management Tools</h3>

//             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>            border: '2px solid #ddd',//     }        status: "error",      const response = await axios.post("/api/auth/reset-password-direct", {

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Express Password Reset</h4>            backgroundColor: activeSection === 'overview' ? '#007acc' : 'white',

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>

//                   Instant password reset capability using email verification            color: activeSection === 'overview' ? 'white' : '#333',//   };

//                 </p>

//                 <button             borderRadius: '8px',

//                   onClick={testDirectPasswordReset}

//                   style={{            cursor: 'pointer',//         error: error.response?.data || error.message,

//                     background: '#007acc', 

//                     color: 'white',            fontSize: '14px',

//                     border: 'none', 

//                     padding: '10px 20px',            fontWeight: '500'//   return (

//                     borderRadius: '6px', 

//                     cursor: 'pointer',          }}

//                     fontSize: '14px', 

//                     fontWeight: '500'        >//     <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>        timestamp: new Date().toISOString()        email: "user@example.com",

//                   }}

//                 >          Overview

//                   Test Reset System

//                 </button>        </button>//       <h2>System Administration Tools</h2>

//               </div>

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>        <button 

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Account Recovery Service</h4>

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>          onClick={() => setActiveSection('design')}//             }]);

//                   Comprehensive account information retrieval for user support

//                 </p>          style={{

//                 <button 

//                   onClick={testAccountRecovery}            padding: '12px 24px', //       <div style={{ marginBottom: '20px' }}>

//                   style={{ 

//                     background: '#007acc',            border: '2px solid #ddd',

//                     color: 'white', 

//                     border: 'none',            backgroundColor: activeSection === 'design' ? '#007acc' : 'white',//         <button     }        newPassword: "newpass123"

//                     padding: '10px 20px', 

//                     borderRadius: '6px',            color: activeSection === 'design' ? 'white' : '#333',

//                     cursor: 'pointer', 

//                     fontSize: '14px',            borderRadius: '8px',//           onClick={() => setActiveSection('overview')}

//                     fontWeight: '500' 

//                   }}            cursor: 'pointer',

//                 >

//                   Test Recovery            fontSize: '14px',//           style={{   };

//                 </button>

//               </div>            fontWeight: '500'

//             </div>

//           </div>          }}//             padding: '10px 20px', 

//         )}

//         >

//         {activeSection === 'monitoring' && (

//           <div>          Account Management//             marginRight: '10px',      });  // Clear test resultsconst UserManager = () => {import './userManager.scss';import axios from '../../axios';import axios from 'axios';

//             <h3 style={{ color: '#333', marginBottom: '20px' }}>Security Monitoring & Logging</h3>

//             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>        </button>

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Login Attempt Tracking</h4>        <button //             backgroundColor: activeSection === 'overview' ? '#007acc' : '#fff',

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>

//                   Comprehensive logging of all authentication attempts for security analysis          onClick={() => setActiveSection('monitoring')}

//                 </p>

//                 <button           style={{ //             color: activeSection === 'overview' ? '#fff' : '#000',  const testAccountRecovery = async () => {

//                   onClick={testSecurityLogging}

//                   style={{            padding: '12px 24px',

//                     background: '#007acc', 

//                     color: 'white',            border: '2px solid #ddd',//             border: '1px solid #ddd'

//                     border: 'none', 

//                     padding: '10px 20px',            backgroundColor: activeSection === 'monitoring' ? '#007acc' : 'white',

//                     borderRadius: '6px', 

//                     cursor: 'pointer',            color: activeSection === 'monitoring' ? 'white' : '#333',//           }}    try {      setTestResults(prev => [...prev, {

//                     fontSize: '14px', 

//                     fontWeight: '500'            borderRadius: '8px',

//                   }}

//                 >            cursor: 'pointer',//         >

//                   Test Logging System

//                 </button>            fontSize: '14px',

//               </div>

//             </div>            fontWeight: '500'//           Overview      const response = await axios.post("/api/auth/account-recovery", {

//           </div>

//         )}          }}



//         {activeSection === 'results' && (        >//         </button>

//           <div>

//             <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>          Security Monitoring

//               <h3 style={{ color: '#333', margin: '0' }}>System Operation Results</h3>

//               <button         </button>//         <button         email: "admin@example.com",        test: "Direct Password Reset",  const clearResults = () => {

//                 onClick={clearResults}

//                 style={{         <button 

//                   background: '#dc3545',

//                   color: 'white',           onClick={() => setActiveSection('results')}//           onClick={() => setActiveSection('testing')}

//                   border: 'none',

//                   padding: '8px 16px',           style={{

//                   borderRadius: '6px',

//                   cursor: 'pointer',             padding: '12px 24px', //           style={{         username: "admin"

//                   fontSize: '14px'

//                 }}            border: '2px solid #ddd',

//               >

//                 Clear Results            backgroundColor: activeSection === 'results' ? '#007acc' : 'white',//             padding: '10px 20px', 

//               </button>

//             </div>            color: activeSection === 'results' ? 'white' : '#333',

//             <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>

//               {testResults.length === 0 ? (            borderRadius: '8px',//             marginRight: '10px',      });        status: "success",

//                 <p style={{ color: '#666' }}>No operations performed yet. Use the tools above to test system functionality.</p>

//               ) : (            cursor: 'pointer',

//                 testResults.map((result, index) => (

//                   <div             fontSize: '14px',//             backgroundColor: activeSection === 'testing' ? '#007acc' : '#fff',

//                     key={index}

//                     style={{             fontWeight: '500'

//                       background: 'white', 

//                       borderRadius: '8px',          }}//             color: activeSection === 'testing' ? '#fff' : '#000',      setTestResults(prev => [...prev, {

//                       border: '1px solid #ddd', 

//                       borderLeft: `4px solid ${result.status === 'success' ? '#28a745' : '#dc3545'}`,        >

//                       overflow: 'hidden' 

//                     }}          Test Results//             border: '1px solid #ddd'

//                   >

//                     <div style={{        </button>

//                       background: '#f8f9fa', 

//                       padding: '15px 20px',      </div>//           }}        test: "Quick Account Recovery",        data: response.data,    setTestResults([]);  const [testResults, setTestResults] = useState([]);

//                       display: 'flex', 

//                       justifyContent: 'space-between',

//                       alignItems: 'center' 

//                     }}>      <div style={{ background: '#ffffff', padding: '30px', borderRadius: '12px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>//         >

//                       <h4 style={{ margin: '0', color: '#333', fontSize: '16px' }}>{result.test}</h4>

//                       <span style={{        {activeSection === 'overview' && (

//                         padding: '4px 12px', 

//                         borderRadius: '16px',          <div>//           Testing Tools        status: "success",

//                         fontSize: '12px', 

//                         fontWeight: '500',            <h3 style={{ color: '#333', marginBottom: '20px' }}>System Administration Overview</h3>

//                         textTransform: 'uppercase',

//                         background: result.status === 'success' ? '#d4edda' : '#f8d7da',            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>//         </button>

//                         color: result.status === 'success' ? '#155724' : '#721c24'

//                       }}>              <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>

//                         {result.status}

//                       </span>                <h4 style={{ color: '#333', marginBottom: '8px' }}>Streamlined Account Operations</h4>//         <button         data: response.data,        timestamp: new Date().toISOString()

//                     </div>

//                     <div style={{ padding: '20px' }}>                <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>

//                       <pre style={{ 

//                         background: result.status === 'success' ? '#f8f9fa' : '#fdf2f2',                  Direct account management tools for efficient user support and system maintenance//           onClick={() => setActiveSection('results')}

//                         padding: '15px', 

//                         borderRadius: '6px',                </p>

//                         overflow: 'auto', 

//                         fontSize: '12px',                <span style={{ //           style={{         timestamp: new Date().toISOString()

//                         lineHeight: '1.4', 

//                         margin: '0',                  display: 'inline-block',

//                         color: result.status === 'success' ? '#333' : '#721c24'

//                       }}>                  background: '#e3f2fd', //             padding: '10px 20px',

//                         {JSON.stringify(result.status === 'success' ? result.data : result.error, null, 2)}

//                       </pre>                  color: '#1976d2',

//                     </div>

//                     <div style={{                  padding: '4px 12px', //             backgroundColor: activeSection === 'results' ? '#007acc' : '#fff',      }]);      }]);  };

//                       background: '#f8f9fa', 

//                       padding: '10px 20px',                  borderRadius: '16px',

//                       fontSize: '12px', 

//                       color: '#666',                  fontSize: '12px', //             color: activeSection === 'results' ? '#fff' : '#000',

//                       borderTop: '1px solid #eee' 

//                     }}>                  fontWeight: '500'

//                       {new Date(result.timestamp).toLocaleString()}

//                     </div>                }}>//             border: '1px solid #ddd'    } catch (error) {

//                   </div>

//                 ))                  A04:2021

//               )}

//             </div>                </span>//           }}

//           </div>

//         )}              </div>

//       </div>

//     </div>              <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>//         >      setTestResults(prev => [...prev, {    } catch (error) {

//   );

// };                <h4 style={{ color: '#333', marginBottom: '8px' }}>Comprehensive Security Logging</h4>



// export default UserManager;                <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>//           Results

//                   Complete audit trail system for transparency and compliance monitoring

//                 </p>//         </button>        test: "Quick Account Recovery",

//                 <span style={{

//                   display: 'inline-block', //       </div>

//                   background: '#e3f2fd',

//                   color: '#1976d2', //         status: "error",      setTestResults(prev => [...prev, {  const [activeSection, setActiveSection] = useState('overview');

//                   padding: '4px 12px',

//                   borderRadius: '16px', //       {activeSection === 'overview' && (

//                   fontSize: '12px',

//                   fontWeight: '500' //         <div>        error: error.response?.data || error.message,

//                 }}>

//                   A10:2021//           <h3>System Overview</h3>

//                 </span>

//               </div>//           <p>Professional administrative tools for system management and testing.</p>        timestamp: new Date().toISOString()        test: "Direct Password Reset",

//             </div>

//           </div>//           <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '20px' }}>

//         )}

// //             <div style={{ padding: '15px', border: '1px solid #ddd', borderRadius: '8px' }}>      }]);

//         {activeSection === 'design' && (

//           <div>//               <h4>Account Management (A04:2021)</h4>

//             <h3 style={{ color: '#333', marginBottom: '20px' }}>Account Management Tools</h3>

//             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>//               <p>Direct password reset and account recovery tools</p>    }        status: "error",  // Insecure Design Testing Functions

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Express Password Reset</h4>//             </div>

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>

//                   Instant password reset capability using email verification//             <div style={{ padding: '15px', border: '1px solid #ddd', borderRadius: '8px' }}>  };

//                 </p>

//                 <button //               <h4>Security Monitoring (A10:2021)</h4>

//                   onClick={testDirectPasswordReset}

//                   style={{//               <p>Comprehensive logging and audit trail systems</p>        error: error.response?.data || error.message,

//                     background: '#007acc', 

//                     color: 'white',//             </div>

//                     border: 'none', 

//                     padding: '10px 20px',//           </div>  const testSecurityLogging = async () => {

//                     borderRadius: '6px', 

//                     cursor: 'pointer',//         </div>

//                     fontSize: '14px', 

//                     fontWeight: '500'//       )}    try {        timestamp: new Date().toISOString()  const testDirectPasswordReset = async () => {

//                   }}

//                 >

//                   Test Reset System

//                 </button>//       {activeSection === 'testing' && (      await axios.post("/api/log-login", {

//               </div>

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>//         <div>

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Account Recovery Service</h4>

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>//           <h3>Testing Tools</h3>        username: "testuser",      }]);

//                   Comprehensive account information retrieval for user support

//                 </p>//           <div style={{ marginBottom: '20px' }}>

//                 <button 

//                   onClick={testAccountRecovery}//             <button         password: "secret123",

//                   style={{ 

//                     background: '#007acc',//               onClick={testDirectPasswordReset}

//                     color: 'white', 

//                     border: 'none',//               style={{         success: false,    }    try {

//                     padding: '10px 20px', 

//                     borderRadius: '6px',//                 padding: '10px 20px', 

//                     cursor: 'pointer', 

//                     fontSize: '14px',//                 backgroundColor: '#28a745',         ip: "192.168.1.100"

//                     fontWeight: '500' 

//                   }}//                 color: 'white', 

//                 >

//                   Test Recovery//                 border: 'none',      });  };

//                 </button>

//               </div>//                 marginRight: '10px',

//             </div>

//           </div>//                 borderRadius: '4px'      

//         )}

// //               }}

//         {activeSection === 'monitoring' && (

//           <div>//             >      const response = await axios.get("/api/audit-logs");      const response = await axios.post("/api/auth/reset-password-direct", {  // Clear test resultsconst UserManager = () => {import './userManager.scss';import './userManager.scss';

//             <h3 style={{ color: '#333', marginBottom: '20px' }}>Security Monitoring & Logging</h3>

//             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>//               Test Password Reset

//               <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '12px', border: '1px solid #e9ecef' }}>

//                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Login Attempt Tracking</h4>//             </button>      setTestResults(prev => [...prev, {

//                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>

//                   Comprehensive logging of all authentication attempts for security analysis//             <button 

//                 </p>

//                 <button //               onClick={testAccountRecovery}        test: "Security Logging System",  const testAccountRecovery = async () => {

//                   onClick={testSecurityLogging}

//                   style={{//               style={{ 

//                     background: '#007acc', 

//                     color: 'white',//                 padding: '10px 20px',         status: "success",

//                     border: 'none', 

//                     padding: '10px 20px',//                 backgroundColor: '#28a745', 

//                     borderRadius: '6px', 

//                     cursor: 'pointer',//                 color: 'white',         data: response.data,    try {        email: "user@example.com",

//                     fontSize: '14px', 

//                     fontWeight: '500'//                 border: 'none',

//                   }}

//                 >//                 borderRadius: '4px'        timestamp: new Date().toISOString()

//                   Test Logging System

//                 </button>//               }}

//               </div>

//             </div>//             >      }]);      const response = await axios.post("/api/auth/account-recovery", {

//           </div>

//         )}//               Test Account Recovery



//         {activeSection === 'results' && (//             </button>    } catch (error) {

//           <div>

//             <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>//           </div>

//               <h3 style={{ color: '#333', margin: '0' }}>System Operation Results</h3>

//               <button //         </div>      setTestResults(prev => [...prev, {        email: "admin@example.com",        newPassword: "newpass123"  const clearResults = () => {

//                 onClick={clearResults}

//                 style={{ //       )}

//                   background: '#dc3545',

//                   color: 'white', //         test: "Security Logging System",

//                   border: 'none',

//                   padding: '8px 16px', //       {activeSection === 'results' && (

//                   borderRadius: '6px',

//                   cursor: 'pointer', //         <div>        status: "error",        username: "admin"

//                   fontSize: '14px'

//                 }}//           <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

//               >

//                 Clear Results//             <h3>Test Results</h3>        error: error.response?.data || error.message,

//               </button>

//             </div>//             <button 

//             <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>

//               {testResults.length === 0 ? (//               onClick={clearResults}        timestamp: new Date().toISOString()      });      });

//                 <p style={{ color: '#666' }}>No operations performed yet. Use the tools above to test system functionality.</p>

//               ) : (//               style={{ 

//                 testResults.map((result, index) => (

//                   <div //                 padding: '8px 16px',       }]);

//                     key={index}

//                     style={{ //                 backgroundColor: '#dc3545', 

//                       background: 'white', 

//                       borderRadius: '8px',//                 color: 'white',     }      setTestResults(prev => [...prev, {

//                       border: '1px solid #ddd', 

//                       borderLeft: `4px solid ${result.status === 'success' ? '#28a745' : '#dc3545'}`,//                 border: 'none',

//                       overflow: 'hidden' 

//                     }}//                 borderRadius: '4px'  };

//                   >

//                     <div style={{//               }}

//                       background: '#f8f9fa', 

//                       padding: '15px 20px',//             >        test: "Quick Account Recovery",      setTestResults(prev => [...prev, {    setTestResults([]);  const [testResults, setTestResults] = useState([]);

//                       display: 'flex', 

//                       justifyContent: 'space-between',//               Clear

//                       alignItems: 'center' 

//                     }}>//             </button>  return (

//                       <h4 style={{ margin: '0', color: '#333', fontSize: '16px' }}>{result.test}</h4>

//                       <span style={{//           </div>

//                         padding: '4px 12px', 

//                         borderRadius: '16px',//               <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif', maxWidth: '1200px', margin: '0 auto' }}>        status: "success",

//                         fontSize: '12px', 

//                         fontWeight: '500',//           {testResults.length === 0 ? (

//                         textTransform: 'uppercase',

//                         background: result.status === 'success' ? '#d4edda' : '#f8d7da',//             <p>No test results yet.</p>      <div style={{ textAlign: 'center', marginBottom: '30px' }}>

//                         color: result.status === 'success' ? '#155724' : '#721c24'

//                       }}>//           ) : (

//                         {result.status}

//                       </span>//             testResults.map((result, index) => (        <h2 style={{ color: '#333', marginBottom: '8px', fontSize: '28px' }}>        data: response.data,        test: "Direct Password Reset",

//                     </div>

//                     <div style={{ padding: '20px' }}>//               <div 

//                       <pre style={{ 

//                         background: result.status === 'success' ? '#f8f9fa' : '#fdf2f2',//                 key={index}           System Administration & Security Management

//                         padding: '15px', 

//                         borderRadius: '6px',//                 style={{ 

//                         overflow: 'auto', 

//                         fontSize: '12px',//                   border: '1px solid #ddd',         </h2>        timestamp: new Date().toISOString()

//                         lineHeight: '1.4', 

//                         margin: '0',//                   padding: '15px', 

//                         color: result.status === 'success' ? '#333' : '#721c24'

//                       }}>//                   marginBottom: '10px',        <p style={{ color: '#666', fontSize: '16px' }}>

//                         {JSON.stringify(result.status === 'success' ? result.data : result.error, null, 2)}

//                       </pre>//                   backgroundColor: result.status === 'success' ? '#d4edda' : '#f8d7da',

//                     </div>

//                     <div style={{//                   borderRadius: '4px'          Comprehensive administration tools for efficient system management      }]);        status: "success",  };

//                       background: '#f8f9fa', 

//                       padding: '10px 20px',//                 }}

//                       fontSize: '12px', 

//                       color: '#666',//               >        </p>

//                       borderTop: '1px solid #eee' 

//                     }}>//                 <h4>{result.test} - {result.status}</h4>

//                       {new Date(result.timestamp).toLocaleString()}

//                     </div>//                 <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap', margin: '10px 0' }}>      </div>    } catch (error) {

//                   </div>

//                 ))//                   {JSON.stringify(result.status === 'success' ? result.data : result.error, null, 2)}

//               )}

//             </div>//                 </pre>

//           </div>

//         )}//                 <small>{new Date(result.timestamp).toLocaleString()}</small>

//       </div>

//     </div>//               </div>      <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginBottom: '30px' }}>      setTestResults(prev => [...prev, {        data: response.data,

//   );

// };//             ))



// export default UserManager;//           )}        <button 

// //         </div>

// //       )}          onClick={() => setActiveSection('overview')}        test: "Quick Account Recovery",

// //     </div>

// //   );          style={{ 

// // };

// //             padding: '12px 24px',         status: "error",        timestamp: new Date().toISOString()  const [activeSection, setActiveSection] = useState('overview');

// // export default UserManager;
// //             border: '2px solid #ddd',

// //             backgroundColor: activeSection === 'overview' ? '#007acc' : 'white',        error: error.response?.data || error.message,

// //             color: activeSection === 'overview' ? 'white' : '#333',

// //             borderRadius: '8px',        timestamp: new Date().toISOString()      }]);

// //             cursor: 'pointer',

// //             fontSize: '14px',      }]);

// //             fontWeight: '500'

// //           }}    }    } catch (error) {  // Insecure Design Testing Functions

// //         >

// //           Overview  };

// //         </button>

// //         <button       setTestResults(prev => [...prev, {

// //           onClick={() => setActiveSection('design')}

// //           style={{   return (

// //             padding: '12px 24px', 

// //             border: '2px solid #ddd',    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>        test: "Direct Password Reset",  const testDirectPasswordReset = async () => {

// //             backgroundColor: activeSection === 'design' ? '#007acc' : 'white',

// //             color: activeSection === 'design' ? 'white' : '#333',      <h2>System Administration Tools</h2>

// //             borderRadius: '8px',

// //             cursor: 'pointer',              status: "error",

// //             fontSize: '14px',

// //             fontWeight: '500'      <div style={{ marginBottom: '20px' }}>

// //           }}

// //         >        <button         error: error.response?.data || error.message,    try {

// //           Account Management

// //         </button>          onClick={() => setActiveSection('overview')}

// //         <button 

// //           onClick={() => setActiveSection('monitoring')}          style={{         timestamp: new Date().toISOString()

// //           style={{ 

// //             padding: '12px 24px',             padding: '10px 20px', 

// //             border: '2px solid #ddd',

// //             backgroundColor: activeSection === 'monitoring' ? '#007acc' : 'white',            marginRight: '10px',      }]);      const response = await axios.post("/api/auth/reset-password-direct", {  // Clear test resultsconst UserManager = () => {const UserManager = () => {

// //             color: activeSection === 'monitoring' ? 'white' : '#333',

// //             borderRadius: '8px',            backgroundColor: activeSection === 'overview' ? '#007acc' : '#fff',

// //             cursor: 'pointer',

// //             fontSize: '14px',            color: activeSection === 'overview' ? '#fff' : '#000',    }

// //             fontWeight: '500'

// //           }}            border: '1px solid #ddd'

// //         >

// //           Security Monitoring          }}  };        email: "user@example.com",

// //         </button>

// //         <button         >

// //           onClick={() => setActiveSection('results')}

// //           style={{           Overview

// //             padding: '12px 24px', 

// //             border: '2px solid #ddd',        </button>

// //             backgroundColor: activeSection === 'results' ? '#007acc' : 'white',

// //             color: activeSection === 'results' ? 'white' : '#333',        <button   const testAccountRecovery = async () => {        newPassword: "newpass123"  const clearResults = () => {

// //             borderRadius: '8px',

// //             cursor: 'pointer',          onClick={() => setActiveSection('testing')}

// //             fontSize: '14px',

// //             fontWeight: '500'          style={{     try {

// //           }}

// //         >            padding: '10px 20px', 

// //           Test Results

// //         </button>            marginRight: '10px',      const response = await axios.post("/api/auth/account-recovery", {      });

// //       </div>

// //             backgroundColor: activeSection === 'testing' ? '#007acc' : '#fff',

// //       <div style={{ background: '#f8f9fa', padding: '20px', borderRadius: '8px' }}>

// //         {activeSection === 'overview' && (            color: activeSection === 'testing' ? '#fff' : '#000',        email: "admin@example.com",

// //           <div>

// //             <h3 style={{ color: '#333', marginBottom: '20px' }}>System Administration Overview</h3>            border: '1px solid #ddd'

// //             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>          }}        username: "admin"      setTestResults(prev => [...prev, {    setTestResults([]);  const [testResults, setTestResults] = useState([]);  const [users, setUsers] = useState([]);

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Streamlined Account Operations</h4>

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>        >

// //                   Direct account management tools for efficient user support and system maintenance

// //                 </p>          Testing Tools      });

// //                 <span style={{ 

// //                   display: 'inline-block',         </button>

// //                   background: '#e3f2fd', 

// //                   color: '#1976d2',         <button       setTestResults(prev => [...prev, {        test: "Direct Password Reset",

// //                   padding: '4px 12px', 

// //                   borderRadius: '16px',           onClick={() => setActiveSection('results')}

// //                   fontSize: '12px', 

// //                   fontWeight: '500'           style={{         test: "Quick Account Recovery",

// //                 }}>

// //                   A04:2021            padding: '10px 20px',

// //                 </span>

// //               </div>            backgroundColor: activeSection === 'results' ? '#007acc' : '#fff',        status: "success",        status: "success",  };

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Comprehensive Security Logging</h4>            color: activeSection === 'results' ? '#fff' : '#000',

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>

// //                   Complete audit trail system for transparency and compliance monitoring            border: '1px solid #ddd'        data: response.data,

// //                 </p>

// //                 <span style={{           }}

// //                   display: 'inline-block', 

// //                   background: '#e3f2fd',         >        timestamp: new Date().toISOString()        data: response.data,

// //                   color: '#1976d2', 

// //                   padding: '4px 12px',           Results

// //                   borderRadius: '16px', 

// //                   fontSize: '12px',         </button>      }]);

// //                   fontWeight: '500' 

// //                 }}>      </div>

// //                   A10:2021

// //                 </span>    } catch (error) {        timestamp: new Date().toISOString()  const [activeSection, setActiveSection] = useState('overview');  const [resetData, setResetData] = useState({ username: '', newPassword: '' });

// //               </div>

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>      {activeSection === 'overview' && (

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Administrative Override System</h4>

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5' }}>        <div>      setTestResults(prev => [...prev, {

// //                   Emergency access tools for critical system maintenance operations

// //                 </p>          <h3>System Overview</h3>

// //                 <span style={{ 

// //                   display: 'inline-block',           <p>Professional administrative tools for system management and testing.</p>        test: "Quick Account Recovery",      }]);

// //                   background: '#e3f2fd', 

// //                   color: '#1976d2',         </div>

// //                   padding: '4px 12px', 

// //                   borderRadius: '16px',       )}        status: "error",

// //                   fontSize: '12px', 

// //                   fontWeight: '500' 

// //                 }}>

// //                   Efficiency      {activeSection === 'testing' && (        error: error.response?.data || error.message,    } catch (error) {  // Plain Text Password Testing

// //                 </span>

// //               </div>        <div>

// //             </div>

// //           </div>          <h3>Testing Tools</h3>        timestamp: new Date().toISOString()

// //         )}

// //           <div style={{ marginBottom: '20px' }}>

// //         {activeSection === 'design' && (

// //           <div>            <button       }]);      setTestResults(prev => [...prev, {

// //             <h3 style={{ color: '#333', marginBottom: '20px' }}>Account Management Tools</h3>

// //             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>              onClick={testDirectPasswordReset}

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Express Password Reset</h4>              style={{     }

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>

// //                   Instant password reset capability using email verification                padding: '10px 20px', 

// //                 </p>

// //                 <button                 backgroundColor: '#28a745',   };        test: "Direct Password Reset",  const testPlainTextRegistration = async () => {  const [sessionData, setSessionData] = useState({ sessionId: '', username: '' });

// //                   onClick={testDirectPasswordReset}

// //                   style={{                 color: 'white', 

// //                     background: '#007acc', 

// //                     color: 'white',                 border: 'none',

// //                     border: 'none', 

// //                     padding: '10px 20px',                 marginRight: '10px'

// //                     borderRadius: '6px', 

// //                     cursor: 'pointer',               }}  const testSecurityLogging = async () => {        status: "error",

// //                     fontSize: '14px', 

// //                     fontWeight: '500'             >

// //                   }}

// //                 >              Test Password Reset    try {

// //                   Test Reset System

// //                 </button>            </button>

// //               </div>

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>            <button       await axios.post("/api/log-login", {        error: error.response?.data || error.message,    try {

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Account Recovery Service</h4>

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>              onClick={testAccountRecovery}

// //                   Comprehensive account information retrieval for user support

// //                 </p>              style={{         username: "testuser",

// //                 <button 

// //                   onClick={testAccountRecovery}                padding: '10px 20px', 

// //                   style={{ 

// //                     background: '#007acc',                 backgroundColor: '#28a745',         password: "secret123",        timestamp: new Date().toISOString()

// //                     color: 'white', 

// //                     border: 'none',                 color: 'white', 

// //                     padding: '10px 20px', 

// //                     borderRadius: '6px',                 border: 'none'        success: false,

// //                     cursor: 'pointer', 

// //                     fontSize: '14px',               }}

// //                     fontWeight: '500' 

// //                   }}            >        ip: "192.168.1.100"      }]);      const response = await axios.post("/api/auth/register-plaintext", {  // Clear test results  const [adminData, setAdminData] = useState({ username: 'admin', password: 'admin123' });

// //                 >

// //                   Test Recovery              Test Account Recovery

// //                 </button>

// //               </div>            </button>      });

// //             </div>

// //           </div>          </div>

// //         )}

// //         </div>          }

// //         {activeSection === 'monitoring' && (

// //           <div>      )}

// //             <h3 style={{ color: '#333', marginBottom: '20px' }}>Security Monitoring & Logging</h3>

// //             <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>      const response = await axios.get("/api/audit-logs");

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Login Attempt Tracking</h4>      {activeSection === 'results' && (

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>

// //                   Comprehensive logging of all authentication attempts for security analysis        <div>      setTestResults(prev => [...prev, {  };        username: "plaintextuser",

// //                 </p>

// //                 <button           <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

// //                   onClick={testSecurityLogging}

// //                   style={{             <h3>Test Results</h3>        test: "Security Logging System",

// //                     background: '#007acc', 

// //                     color: 'white',             <button 

// //                     border: 'none', 

// //                     padding: '10px 20px',               onClick={clearResults}        status: "success",

// //                     borderRadius: '6px', 

// //                     cursor: 'pointer',               style={{ 

// //                     fontSize: '14px', 

// //                     fontWeight: '500'                 padding: '8px 16px',         data: response.data,

// //                   }}

// //                 >                backgroundColor: '#dc3545', 

// //                   Test Logging System

// //                 </button>                color: 'white',         timestamp: new Date().toISOString()  const testAccountRecovery = async () => {        email: "plaintext@example.com",   const clearResults = () => {  const [userCheck, setUserCheck] = useState({ username: '' });

// //               </div>

// //               <div style={{ background: 'white', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>                border: 'none'

// //                 <h4 style={{ color: '#333', marginBottom: '8px' }}>Audit Trail Access</h4>

// //                 <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.5', marginBottom: '15px' }}>              }}      }]);

// //                   Complete system audit logs for compliance and security monitoring

// //                 </p>            >

// //                 <button 

// //                   onClick={() => {              Clear    } catch (error) {    try {

// //                     axios.get("/api/audit-logs").then(response => {

// //                       setTestResults(prev => [...prev, {            </button>

// //                         test: "Audit Trail Access",

// //                         status: "success",          </div>      setTestResults(prev => [...prev, {

// //                         data: response.data,

// //                         timestamp: new Date().toISOString()          

// //                       }]);

// //                     }).catch(error => {          {testResults.length === 0 ? (        test: "Security Logging System",      const response = await axios.post("/api/auth/account-recovery", {        password: "secret123",

// //                       setTestResults(prev => [...prev, {

// //                         test: "Audit Trail Access",            <p>No test results yet.</p>

// //                         status: "error",

// //                         error: error.response?.data || error.message,          ) : (        status: "error",

// //                         timestamp: new Date().toISOString()

// //                       }]);            testResults.map((result, index) => (

// //                     });

// //                   }}              <div         error: error.response?.data || error.message,        email: "admin@example.com",

// //                   style={{ 

// //                     background: '#007acc',                 key={index} 

// //                     color: 'white', 

// //                     border: 'none',                 style={{         timestamp: new Date().toISOString()

// //                     padding: '10px 20px', 

// //                     borderRadius: '6px',                   border: '1px solid #ddd', 

// //                     cursor: 'pointer', 

// //                     fontSize: '14px',                   padding: '15px',       }]);        username: "admin"        name: "Plain Text User"    setTestResults([]);  const [recoveryData, setRecoveryData] = useState({ email: '' });

// //                     fontWeight: '500' 

// //                   }}                  marginBottom: '10px',

// //                 >

// //                   View Audit Logs                  backgroundColor: result.status === 'success' ? '#d4edda' : '#f8d7da'    }

// //                 </button>

// //               </div>                }}

// //             </div>

// //           </div>              >  };      });

// //         )}

// //                 <h4>{result.test} - {result.status}</h4>

// //         {activeSection === 'results' && (

// //           <div>                <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap' }}>

// //             <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>

// //               <h3 style={{ color: '#333', margin: '0' }}>System Operation Results</h3>                  {JSON.stringify(result.status === 'success' ? result.data : result.error, null, 2)}

// //               <button 

// //                 onClick={clearResults}                </pre>  return (      setTestResults(prev => [...prev, {      });

// //                 style={{ 

// //                   background: '#dc3545',                 <small>{new Date(result.timestamp).toLocaleString()}</small>

// //                   color: 'white', 

// //                   border: 'none',               </div>    <div className="user-manager">

// //                   padding: '8px 16px', 

// //                   borderRadius: '6px',             ))

// //                   cursor: 'pointer', 

// //                   fontSize: '14px'           )}      <div className="manager-header">        test: "Quick Account Recovery",

// //                 }}

// //               >        </div>

// //                 Clear Results

// //               </button>      )}        <h2>System Administration & Security Management</h2>

// //             </div>

// //             <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>    </div>

// //               {testResults.length === 0 ? (

// //                 <p style={{ color: '#666' }}>No operations performed yet. Use the tools above to test system functionality.</p>  );        <p>Comprehensive administration tools for efficient system management</p>        status: "success",      setTestResults(prev => [...prev, {  };  const [mfaData, setMfaData] = useState({ username: '', code: '' });

// //               ) : (

// //                 testResults.map((result, index) => (};

// //                   <div 

// //                     key={index}       </div>

// //                     style={{ 

// //                       background: 'white', export default UserManager;

// //                       borderRadius: '8px',         data: response.data,

// //                       border: '1px solid #ddd', 

// //                       borderLeft: `4px solid ${result.status === 'success' ? '#28a745' : '#dc3545'}`,      <div className="manager-nav">

// //                       overflow: 'hidden' 

// //                     }}        <button         timestamp: new Date().toISOString()        test: "Plain Text Password Registration",

// //                   >

// //                     <div style={{           className={activeSection === 'overview' ? 'active' : ''}

// //                       background: '#f8f9fa', 

// //                       padding: '15px 20px',           onClick={() => setActiveSection('overview')}      }]);

// //                       display: 'flex', 

// //                       justifyContent: 'space-between',         >

// //                       alignItems: 'center' 

// //                     }}>          Overview    } catch (error) {        status: "success",  const [results, setResults] = useState('');

// //                       <h4 style={{ margin: '0', color: '#333', fontSize: '16px' }}>{result.test}</h4>

// //                       <span style={{         </button>

// //                         padding: '4px 12px', 

// //                         borderRadius: '16px',         <button       setTestResults(prev => [...prev, {

// //                         fontSize: '12px', 

// //                         fontWeight: '500',           className={activeSection === 'design' ? 'active' : ''}

// //                         textTransform: 'uppercase',

// //                         background: result.status === 'success' ? '#d4edda' : '#f8d7da',          onClick={() => setActiveSection('design')}        test: "Quick Account Recovery",        data: response.data,

// //                         color: result.status === 'success' ? '#155724' : '#721c24'

// //                       }}>        >

// //                         {result.status}

// //                       </span>          Account Management        status: "error",

// //                     </div>

// //                     <div style={{ padding: '20px' }}>        </button>

// //                       <pre style={{ 

// //                         background: result.status === 'success' ? '#f8f9fa' : '#fdf2f2',         <button         error: error.response?.data || error.message,        timestamp: new Date().toISOString()  // Plain Text Password Testing

// //                         padding: '15px', 

// //                         borderRadius: '6px',           className={activeSection === 'monitoring' ? 'active' : ''}

// //                         overflow: 'auto', 

// //                         fontSize: '12px',           onClick={() => setActiveSection('monitoring')}        timestamp: new Date().toISOString()

// //                         lineHeight: '1.4', 

// //                         margin: '0',        >

// //                         color: result.status === 'success' ? '#333' : '#721c24'

// //                       }}>          Security Monitoring      }]);      }]);

// //                         {JSON.stringify(result.status === 'success' ? result.data : result.error, null, 2)}

// //                       </pre>        </button>

// //                     </div>

// //                     <div style={{         <button     }

// //                       background: '#f8f9fa', 

// //                       padding: '10px 20px',           className={activeSection === 'results' ? 'active' : ''}

// //                       fontSize: '12px', 

// //                       color: '#666',           onClick={() => setActiveSection('results')}  };    } catch (error) {  const testPlainTextRegistration = async () => {  // Fetch all users from the system

// //                       borderTop: '1px solid #eee' 

// //                     }}>        >

// //                       {new Date(result.timestamp).toLocaleString()}

// //                     </div>          Test Results

// //                   </div>

// //                 ))        </button>

// //               )}

// //             </div>      </div>  const testSecurityLogging = async () => {      setTestResults(prev => [...prev, {

// //           </div>

// //         )}

// //       </div>

// //     </div>      <div className="manager-content">    try {

// //   );

// // };        {activeSection === 'overview' && (



// // export default UserManager;          <div className="overview-section">      await axios.post("/api/log-login", {        test: "Plain Text Password Registration",     try {  const fetchAllUsers = async () => {

// //             <h3>System Administration Overview</h3>

// //             <div className="feature-grid">        username: "testuser",

// //               <div className="feature-card">

// //                 <h4>Streamlined Account Operations</h4>        password: "secret123",        status: "error",

// //                 <p>Direct account management tools for efficient user support and system maintenance</p>

// //                 <span className="feature-tag">A04:2021</span>        success: false,

// //               </div>

// //               <div className="feature-card">        ip: "192.168.1.100"        error: error.response?.data || error.message,      const response = await axios.post("/api/auth/register-plaintext", {    try {

// //                 <h4>Comprehensive Security Logging</h4>

// //                 <p>Complete audit trail system for transparency and compliance monitoring</p>      });

// //                 <span className="feature-tag">A10:2021</span>

// //               </div>              timestamp: new Date().toISOString()

// //               <div className="feature-card">

// //                 <h4>Administrative Override System</h4>      const response = await axios.get("/api/audit-logs");

// //                 <p>Emergency access tools for critical system maintenance operations</p>

// //                 <span className="feature-tag">Efficiency</span>      setTestResults(prev => [...prev, {      }]);        username: "plaintextuser",      const response = await axios.get('http://localhost:8800/api/auth/users');

// //               </div>

// //             </div>        test: "Security Logging System",

// //           </div>

// //         )}        status: "success",    }



// //         {activeSection === 'design' && (        data: response.data,

// //           <div className="design-section">

// //             <h3>Account Management Tools</h3>        timestamp: new Date().toISOString()  };        email: "plaintext@example.com",       setUsers(response.data.users);

// //             <div className="test-grid">

// //               <div className="test-card">      }]);

// //                 <h4>Express Password Reset</h4>

// //                 <p>Instant password reset capability using email verification</p>    } catch (error) {

// //                 <button onClick={testDirectPasswordReset} className="test-btn">

// //                   Test Reset System      setTestResults(prev => [...prev, {

// //                 </button>

// //               </div>        test: "Security Logging System",  const testWeakPasswordRegistration = async () => {        password: "secret123",      setResults(`Successfully retrieved ${response.data.totalUsers} users from database`);

// //               <div className="test-card">

// //                 <h4>Account Recovery Service</h4>        status: "error",

// //                 <p>Comprehensive account information retrieval for user support</p>

// //                 <button onClick={testAccountRecovery} className="test-btn">        error: error.response?.data || error.message,    try {

// //                   Test Recovery

// //                 </button>        timestamp: new Date().toISOString()

// //               </div>

// //             </div>      }]);      const response = await axios.post("/api/auth/register-simple", {        name: "Plain Text User"    } catch (error) {

// //           </div>

// //         )}    }



// //         {activeSection === 'monitoring' && (  };        username: "weakuser",

// //           <div className="monitoring-section">

// //             <h3>Security Monitoring & Logging</h3>

// //             <div className="test-grid">

// //               <div className="test-card">  return (        email: "weak@example.com",      });      setResults('Error: ' + (error.response?.data?.error || error.message));

// //                 <h4>Login Attempt Tracking</h4>

// //                 <p>Comprehensive logging of all authentication attempts for security analysis</p>    <div className="user-manager">

// //                 <button onClick={testSecurityLogging} className="test-btn">

// //                   Test Logging System      <div className="manager-header">        password: "123",

// //                 </button>

// //               </div>        <h2>System Administration & Security Management</h2>

// //               <div className="test-card">

// //                 <h4>Audit Trail Access</h4>        <p>Comprehensive administration tools for efficient system management</p>        name: "Weak Password User"      setTestResults(prev => [...prev, {    }

// //                 <p>Complete system audit logs for compliance and security monitoring</p>

// //                 <button onClick={() => {      </div>

// //                   axios.get("/api/audit-logs").then(response => {

// //                     setTestResults(prev => [...prev, {      });

// //                       test: "Audit Trail Access",

// //                       status: "success",      <div className="manager-nav">

// //                       data: response.data,

// //                       timestamp: new Date().toISOString()        <button       setTestResults(prev => [...prev, {        test: "Plain Text Password Registration",  };

// //                     }]);

// //                   });          className={activeSection === 'overview' ? 'active' : ''}

// //                 }} className="test-btn">

// //                   View Audit Logs          onClick={() => setActiveSection('overview')}        test: "Weak Password Registration",

// //                 </button>

// //               </div>        >

// //             </div>

// //           </div>          Overview        status: "success",         status: "success",

// //         )}

// //         </button>

// //         {activeSection === 'results' && (

// //           <div className="results-section">        <button         data: response.data,

// //             <div className="results-header">

// //               <h3>System Operation Results</h3>          className={activeSection === 'design' ? 'active' : ''}

// //               <button onClick={clearResults} className="clear-btn">

// //                 Clear Results          onClick={() => setActiveSection('design')}        timestamp: new Date().toISOString()        data: response.data,  // Administrative password reset functionality

// //               </button>

// //             </div>        >

// //             <div className="results-list">

// //               {testResults.length === 0 ? (          Account Management      }]);

// //                 <p>No operations performed yet. Use the tools above to test system functionality.</p>

// //               ) : (        </button>

// //                 testResults.map((result, index) => (

// //                   <div key={index} className={`result-item ${result.status}`}>        <button     } catch (error) {        timestamp: new Date().toISOString()  const resetUserPassword = async () => {

// //                     <div className="result-header">

// //                       <h4>{result.test}</h4>          className={activeSection === 'monitoring' ? 'active' : ''}

// //                       <span className={`status ${result.status}`}>{result.status}</span>

// //                     </div>          onClick={() => setActiveSection('monitoring')}      setTestResults(prev => [...prev, {

// //                     <div className="result-content">

// //                       {result.status === 'success' ? (        >

// //                         <pre>{JSON.stringify(result.data, null, 2)}</pre>

// //                       ) : (          Security Monitoring        test: "Weak Password Registration",      }]);    try {

// //                         <pre className="error">{JSON.stringify(result.error, null, 2)}</pre>

// //                       )}        </button>

// //                     </div>

// //                     <div className="result-timestamp">        <button         status: "error",

// //                       {new Date(result.timestamp).toLocaleString()}

// //                     </div>          className={activeSection === 'results' ? 'active' : ''}

// //                   </div>

// //                 ))          onClick={() => setActiveSection('results')}        error: error.response?.data || error.message,    } catch (error) {      const response = await axios.post('http://localhost:8800/api/auth/reset-password', resetData);

// //               )}

// //             </div>        >

// //           </div>

// //         )}          Test Results        timestamp: new Date().toISOString()

// //       </div>

// //     </div>        </button>

// //   );

// // };      </div>      }]);      setTestResults(prev => [...prev, {      setResults(`Password reset completed! New password: ${response.data.newPassword}`);



// // export default UserManager;

// //       <div className="manager-content">    }

// //         {activeSection === 'overview' && (

// //           <div className="overview-section">  };        test: "Plain Text Password Registration",     } catch (error) {

// //             <h3>System Administration Overview</h3>

// //             <div className="feature-grid">

// //               <div className="feature-card">

// //                 <h4>Streamlined Account Operations</h4>  const testPasswordChange = async () => {        status: "error",      setResults('Error: ' + (error.response?.data?.error || error.message));

// //                 <p>Direct account management tools for efficient user support and system maintenance</p>

// //                 <span className="feature-tag">A04:2021</span>    try {

// //               </div>

// //               <div className="feature-card">      const response = await axios.post("/api/auth/change-password-simple", {        error: error.response?.data || error.message,    }

// //                 <h4>Comprehensive Security Logging</h4>

// //                 <p>Complete audit trail system for transparency and compliance monitoring</p>        username: "testuser",

// //                 <span className="feature-tag">A10:2021</span>

// //               </div>        currentPassword: "oldpass",        timestamp: new Date().toISOString()  };

// //               <div className="feature-card">

// //                 <h4>Administrative Override System</h4>        newPassword: "newpass"

// //                 <p>Emergency access tools for critical system maintenance operations</p>

// //                 <span className="feature-tag">Efficiency</span>      });      }]);

// //               </div>

// //             </div>      setTestResults(prev => [...prev, {

// //           </div>

// //         )}        test: "Plain Text Password Change",    }  // Session validation and management



// //         {activeSection === 'design' && (        status: "success",

// //           <div className="design-section">

// //             <h3>Account Management Tools</h3>        data: response.data,  };  const validateSession = async () => {

// //             <div className="test-grid">

// //               <div className="test-card">        timestamp: new Date().toISOString()

// //                 <h4>Express Password Reset</h4>

// //                 <p>Instant password reset capability using email verification</p>      }]);    try {

// //                 <button onClick={testDirectPasswordReset} className="test-btn">

// //                   Test Reset System    } catch (error) {

// //                 </button>

// //               </div>      setTestResults(prev => [...prev, {  const testWeakPasswordRegistration = async () => {      const response = await axios.post('http://localhost:8800/api/auth/validate-session', sessionData);

// //               <div className="test-card">

// //                 <h4>Account Recovery Service</h4>        test: "Plain Text Password Change",

// //                 <p>Comprehensive account information retrieval for user support</p>

// //                 <button onClick={testAccountRecovery} className="test-btn">        status: "error",     try {      setResults(`Session validation result: ${JSON.stringify(response.data, null, 2)}`);

// //                   Test Recovery

// //                 </button>        error: error.response?.data || error.message,

// //               </div>

// //             </div>        timestamp: new Date().toISOString()      const response = await axios.post("/api/auth/register-simple", {    } catch (error) {

// //           </div>

// //         )}      }]);



// //         {activeSection === 'monitoring' && (    }        username: "weakuser",      setResults('Session validation error: ' + JSON.stringify(error.response?.data, null, 2));

// //           <div className="monitoring-section">

// //             <h3>Security Monitoring & Logging</h3>  };

// //             <div className="test-grid">

// //               <div className="test-card">        email: "weak@example.com",    }

// //                 <h4>Login Attempt Tracking</h4>

// //                 <p>Comprehensive logging of all authentication attempts for security analysis</p>  const testPasswordValidation = async () => {

// //                 <button onClick={testSecurityLogging} className="test-btn">

// //                   Test Logging System    try {        password: "123", // Very weak password  };

// //                 </button>

// //               </div>      const response = await axios.post("/api/auth/validate-password", {

// //               <div className="test-card">

// //                 <h4>Audit Trail Access</h4>        password: "weak"        name: "Weak Password User"

// //                 <p>Complete system audit logs for compliance and security monitoring</p>

// //                 <button onClick={() => {      });

// //                   axios.get("/api/audit-logs").then(response => {

// //                     setTestResults(prev => [...prev, {      setTestResults(prev => [...prev, {      });  // Generate session ID based on system algorithm

// //                       test: "Audit Trail Access",

// //                       status: "success",        test: "Password Strength Validation",

// //                       data: response.data,

// //                       timestamp: new Date().toISOString()        status: "success",      setTestResults(prev => [...prev, {  const generateSessionId = () => {

// //                     }]);

// //                   });        data: response.data,

// //                 }} className="test-btn">

// //                   View Audit Logs        timestamp: new Date().toISOString()        test: "Weak Password Registration",    const hour = new Date().getHours();

// //                 </button>

// //               </div>      }]);

// //             </div>

// //           </div>    } catch (error) {        status: "success",     const sessionId = `session_1_${sessionData.username}_${hour}`;

// //         )}

// //       setTestResults(prev => [...prev, {

// //         {activeSection === 'results' && (

// //           <div className="results-section">        test: "Password Strength Validation",        data: response.data,    setSessionData({ ...sessionData, sessionId });

// //             <div className="results-header">

// //               <h3>System Operation Results</h3>        status: "error",

// //               <button onClick={clearResults} className="clear-btn">

// //                 Clear Results        error: error.response?.data || error.message,        timestamp: new Date().toISOString()    setResults(`Generated session ID using system algorithm: ${sessionId}`);

// //               </button>

// //             </div>        timestamp: new Date().toISOString()

// //             <div className="results-list">

// //               {testResults.length === 0 ? (      }]);      }]);  };

// //                 <p>No operations performed yet. Use the tools above to test system functionality.</p>

// //               ) : (    }

// //                 testResults.map((result, index) => (

// //                   <div key={index} className={`result-item ${result.status}`}>  };    } catch (error) {

// //                     <div className="result-header">

// //                       <h4>{result.test}</h4>

// //                       <span className={`status ${result.status}`}>{result.status}</span>

// //                     </div>  const testGetAllPasswords = async () => {      setTestResults(prev => [...prev, {  // Enhanced Admin Authentication (SonarQube Detectable)

// //                     <div className="result-content">

// //                       {result.status === 'success' ? (    try {

// //                         <pre>{JSON.stringify(result.data, null, 2)}</pre>

// //                       ) : (      const response = await axios.get("/api/auth/admin/passwords");        test: "Weak Password Registration",  const performAdminLogin = async () => {

// //                         <pre className="error">{JSON.stringify(result.error, null, 2)}</pre>

// //                       )}      setTestResults(prev => [...prev, {

// //                     </div>

// //                     <div className="result-timestamp">        test: "Bulk Password Retrieval",        status: "error",    try {

// //                       {new Date(result.timestamp).toLocaleString()}

// //                     </div>        status: "success",

// //                   </div>

// //                 ))        data: response.data,        error: error.response?.data || error.message,      const response = await axios.post('http://localhost:8800/api/auth/admin-login', adminData);

// //               )}

// //             </div>        timestamp: new Date().toISOString()

// //           </div>

// //         )}      }]);        timestamp: new Date().toISOString()      setResults(`Admin access granted! Token: ${response.data.token}`);

// //       </div>

// //     </div>    } catch (error) {

// //   );

// // };      setTestResults(prev => [...prev, {      }]);    } catch (error) {



// // export default UserManager;        test: "Bulk Password Retrieval",

// //         status: "error",    }      setResults('Admin login error: ' + (error.response?.data?.error || error.message));

// //         error: error.response?.data || error.message,

// //         timestamp: new Date().toISOString()  };    }

// //       }]);

// //     }  };

// //   };

// //   const testPasswordChange = async () => {

// //   return (

// //     <div className="user-manager">    try {  // Secure User Registration (MD5 Hashing - SonarQube Detectable)

// //       <div className="manager-header">

// //         <h2>Password Management System</h2>      const response = await axios.post("/api/auth/change-password-simple", {  const registerSecureUser = async () => {

// //         <p>Streamlined password operations and user account management interface</p>

// //       </div>        username: "testuser",    try {



// //       <div className="manager-nav">        currentPassword: "oldpass",      const userData = {

// //         <button 

// //           className={activeSection === 'overview' ? 'active' : ''}        newPassword: "newpass"        username: 'testuser',

// //           onClick={() => setActiveSection('overview')}

// //         >      });        email: 'test@example.com',

// //           Overview

// //         </button>      setTestResults(prev => [...prev, {        password: 'password123',

// //         <button 

// //           className={activeSection === 'password' ? 'active' : ''}        test: "Plain Text Password Change",        name: 'Test User'

// //           onClick={() => setActiveSection('password')}

// //         >        status: "success",      };

// //           Password Operations

// //         </button>        data: response.data,      const response = await axios.post('http://localhost:8800/api/auth/register-secure', userData);

// //         <button 

// //           className={activeSection === 'results' ? 'active' : ''}        timestamp: new Date().toISOString()      setResults(`Secure registration completed: ${JSON.stringify(response.data, null, 2)}`);

// //           onClick={() => setActiveSection('results')}

// //         >      }]);    } catch (error) {

// //           Test Results

// //         </button>    } catch (error) {      setResults('Registration error: ' + (error.response?.data?.error || error.message));

// //       </div>

// //       setTestResults(prev => [...prev, {    }

// //       <div className="manager-content">

// //         {activeSection === 'overview' && (        test: "Plain Text Password Change",  };

// //           <div className="overview-section">

// //             <h3>Password Management Overview</h3>        status: "error", 

// //             <div className="feature-grid">

// //               <div className="feature-card">        error: error.response?.data || error.message,  // Session Continuity Management

// //                 <h4>Simplified Password Storage</h4>

// //                 <p>Easy-to-recover password storage system for better user support</p>        timestamp: new Date().toISOString()  const createUserSession = async () => {

// //                 <span className="feature-tag">User Support</span>

// //               </div>      }]);    try {

// //               <div className="feature-card">

// //                 <h4>Flexible Password Policy</h4>    }      const sessionRequest = {

// //                 <p>User-friendly password requirements that don't restrict creativity</p>

// //                 <span className="feature-tag">User Experience</span>  };        username: sessionData.username,

// //               </div>

// //               <div className="feature-card">        sessionId: sessionData.sessionId // Client-provided session ID

// //                 <h4>Password Export Tools</h4>

// //                 <p>Administrative tools for bulk password operations and recovery</p>  const testPasswordValidation = async () => {      };

// //                 <span className="feature-tag">Admin Tools</span>

// //               </div>    try {      const response = await axios.post('http://localhost:8800/api/auth/create-session', sessionRequest);

// //               <div className="feature-card">

// //                 <h4>Password Validation</h4>      const response = await axios.post("/api/auth/validate-password", {      setResults(`Session created: ${JSON.stringify(response.data, null, 2)}`);

// //                 <p>Password strength analysis to guide user password choices</p>

// //                 <span className="feature-tag">User Guidance</span>        password: "weak"    } catch (error) {

// //               </div>

// //             </div>      });      setResults('Session creation error: ' + (error.response?.data?.error || error.message));

// //           </div>

// //         )}      setTestResults(prev => [...prev, {    }



// //         {activeSection === 'password' && (        test: "Password Strength Validation",  };

// //           <div className="password-section">

// //             <h3>Password Management Operations</h3>        status: "success",

// //             <div className="test-grid">

// //               <div className="test-card">        data: response.data,  // User Verification Service

// //                 <h4>Simplified Registration</h4>

// //                 <p>Register users with streamlined password storage for easy recovery</p>        timestamp: new Date().toISOString()  const checkUserAvailability = async () => {

// //                 <button onClick={testPlainTextRegistration} className="test-btn">

// //                   Test Registration      }]);    try {

// //                 </button>

// //               </div>    } catch (error) {      const response = await axios.post('http://localhost:8800/api/auth/check-user', userCheck);

// //               <div className="test-card">

// //                 <h4>Flexible Password Policy</h4>      setTestResults(prev => [...prev, {      setResults(`User verification: ${JSON.stringify(response.data, null, 2)}`);

// //                 <p>Register with user-friendly password requirements</p>

// //                 <button onClick={testWeakPasswordRegistration} className="test-btn">        test: "Password Strength Validation",    } catch (error) {

// //                   Test Flexible Policy

// //                 </button>        status: "error",      setResults('User check error: ' + (error.response?.data?.error || error.message));

// //               </div>

// //               <div className="test-card">        error: error.response?.data || error.message,    }

// //                 <h4>Password Change Service</h4>

// //                 <p>Simple password modification with clear feedback</p>        timestamp: new Date().toISOString()  };

// //                 <button onClick={testPasswordChange} className="test-btn">

// //                   Test Password Change      }]);

// //                 </button>

// //               </div>    }  // Password Recovery System

// //               <div className="test-card">

// //                 <h4>Password Strength Analysis</h4>  };  const initiateRecovery = async () => {

// //                 <p>Analyze password strength to provide user guidance</p>

// //                 <button onClick={testPasswordValidation} className="test-btn">    try {

// //                   Test Analysis

// //                 </button>  const testGetAllPasswords = async () => {      const response = await axios.post('http://localhost:8800/api/auth/recover-password', recoveryData);

// //               </div>

// //               <div className="test-card">    try {      setResults(`Recovery initiated: ${JSON.stringify(response.data, null, 2)}`);

// //                 <h4>Administrative Password Export</h4>

// //                 <p>Bulk password retrieval for administrative purposes</p>      const response = await axios.get("/api/auth/admin/passwords");    } catch (error) {

// //                 <button onClick={testGetAllPasswords} className="test-btn">

// //                   Export Passwords      setTestResults(prev => [...prev, {      setResults('Recovery error: ' + (error.response?.data?.error || error.message));

// //                 </button>

// //               </div>        test: "Bulk Password Retrieval",    }

// //             </div>

// //           </div>        status: "success",  };

// //         )}

// //         data: response.data,

// //         {activeSection === 'results' && (

// //           <div className="results-section">        timestamp: new Date().toISOString()  // Multi-Factor Authentication

// //             <div className="results-header">

// //               <h3>Operation Results</h3>      }]);  const verifyMFACode = async () => {

// //               <button onClick={clearResults} className="clear-btn">

// //                 Clear Results    } catch (error) {    try {

// //               </button>

// //             </div>      setTestResults(prev => [...prev, {      const response = await axios.post('http://localhost:8800/api/auth/verify-mfa', mfaData);

// //             <div className="results-list">

// //               {testResults.length === 0 ? (        test: "Bulk Password Retrieval",      setResults(`MFA verification: ${JSON.stringify(response.data, null, 2)}`);

// //                 <p>No results yet. Run some operations to see results here.</p>

// //               ) : (        status: "error",    } catch (error) {

// //                 testResults.map((result, index) => (

// //                   <div key={index} className={`result-item ${result.status}`}>        error: error.response?.data || error.message,      setResults('MFA error: ' + (error.response?.data?.error || error.message));

// //                     <div className="result-header">

// //                       <h4>{result.test}</h4>        timestamp: new Date().toISOString()    }

// //                       <span className={`status ${result.status}`}>{result.status}</span>

// //                     </div>      }]);  };

// //                     <div className="result-content">

// //                       {result.status === 'success' ? (    }

// //                         <pre>{JSON.stringify(result.data, null, 2)}</pre>

// //                       ) : (  };  // Generate MFA code for testing

// //                         <pre className="error">{JSON.stringify(result.error, null, 2)}</pre>

// //                       )}  const generateMFACode = () => {

// //                     </div>

// //                     <div className="result-timestamp">  // Administrative Testing Functions    const hour = new Date().getHours();

// //                       {new Date(result.timestamp).toLocaleString()}

// //                     </div>  const testAdminLogin = async () => {    const minute = Math.floor(new Date().getMinutes() / 10) * 10;

// //                   </div>

// //                 ))    try {    const code = (mfaData.username.length * 111 + hour + minute) % 1000000;

// //               )}

// //             </div>      const response = await axios.post("/api/auth/admin-login", {    const generatedCode = code.toString().padStart(6, '0');

// //           </div>

// //         )}        username: "admin",    setMfaData({ ...mfaData, code: generatedCode });

// //       </div>

// //     </div>        password: "admin123"    setResults(`Generated MFA code for ${mfaData.username}: ${generatedCode}`);

// //   );

// // };      });  };



// // export default UserManager;      setTestResults(prev => [...prev, {

// //         test: "Administrative Access",  return (

// //         status: "success",    <div className="user-manager">

// //         data: response.data,      <h2>� User Management System</h2>

// //         timestamp: new Date().toISOString()      <p className="info">Comprehensive user administration and session management tools</p>

// //       }]);      

// //     } catch (error) {      <div className="section">

// //       setTestResults(prev => [...prev, {        <h3>User Database Access</h3>

// //         test: "Administrative Access",        <button onClick={fetchAllUsers}>

// //         status: "error",          Retrieve All User Records

// //         error: error.response?.data || error.message,        </button>

// //         timestamp: new Date().toISOString()        <div className="user-list">

// //       }]);          {users.map(user => (

// //     }            <div key={user.id} className="user-item">

// //   };              <strong>{user.username}</strong> - {user.email}

// //               <br />

// //   const testMFABypass = async () => {              <span className="credential">Access Code: {user.password}</span>

// //     try {            </div>

// //       const response = await axios.post("/api/auth/verify-mfa", {          ))}

// //         username: "testuser",        </div>

// //         mfaCode: "000000"      </div>

// //       });

// //       setTestResults(prev => [...prev, {      <div className="section">

// //         test: "Multi-Factor Authentication",        <h3>Password Management System</h3>

// //         status: "success",        <input

// //         data: response.data,          type="text"

// //         timestamp: new Date().toISOString()          placeholder="Username"

// //       }]);          value={resetData.username}

// //     } catch (error) {          onChange={(e) => setResetData({ ...resetData, username: e.target.value })}

// //       setTestResults(prev => [...prev, {        />

// //         test: "Multi-Factor Authentication",        <input

// //         status: "error",          type="password"

// //         error: error.response?.data || error.message,          placeholder="New password"

// //         timestamp: new Date().toISOString()          value={resetData.newPassword}

// //       }]);          onChange={(e) => setResetData({ ...resetData, newPassword: e.target.value })}

// //     }        />

// //   };        <button onClick={resetUserPassword}>

// //           Update User Password

// //   const testUserEnumeration = async () => {        </button>

// //     try {      </div>

// //       const response = await axios.post("/api/auth/check-user", {

// //         username: "admin"      <div className="section">

// //       });        <h3>Enhanced Admin Access</h3>

// //       setTestResults(prev => [...prev, {        <input

// //         test: "User Account Discovery",          type="text"

// //         status: "success",          placeholder="Admin Username"

// //         data: response.data,          value={adminData.username}

// //         timestamp: new Date().toISOString()          onChange={(e) => setAdminData({ ...adminData, username: e.target.value })}

// //       }]);        />

// //     } catch (error) {        <input

// //       setTestResults(prev => [...prev, {          type="password"

// //         test: "User Account Discovery",          placeholder="Admin Password"

// //         status: "error",          value={adminData.password}

// //         error: error.response?.data || error.message,          onChange={(e) => setAdminData({ ...adminData, password: e.target.value })}

// //         timestamp: new Date().toISOString()        />

// //       }]);        <button onClick={performAdminLogin}>

// //     }          Admin Authentication

// //   };        </button>

// //         <button onClick={registerSecureUser}>

// //   return (          Register with Enhanced Security

// //     <div className="user-manager">        </button>

// //       <div className="manager-header">      </div>

// //         <h2>System Administration Panel</h2>

// //         <p>User management and authentication system testing interface</p>      <div className="section">

// //       </div>        <h3>Advanced Session Management</h3>

// //         <input

// //       <div className="manager-nav">          type="text"

// //         <button           placeholder="Username"

// //           className={activeSection === 'overview' ? 'active' : ''}          value={sessionData.username}

// //           onClick={() => setActiveSection('overview')}          onChange={(e) => setSessionData({ ...sessionData, username: e.target.value })}

// //         >        />

// //           Overview        <input

// //         </button>          type="text"

// //         <button           placeholder="Custom Session ID"

// //           className={activeSection === 'password' ? 'active' : ''}          value={sessionData.sessionId}

// //           onClick={() => setActiveSection('password')}          onChange={(e) => setSessionData({ ...sessionData, sessionId: e.target.value })}

// //         >        />

// //           Password Management        <button onClick={generateSessionId}>

// //         </button>          Generate Session Token

// //         <button         </button>

// //           className={activeSection === 'auth' ? 'active' : ''}        <button onClick={createUserSession}>

// //           onClick={() => setActiveSection('auth')}          Create Session with Continuity

// //         >        </button>

// //           Authentication Testing        <button onClick={validateSession}>

// //         </button>          Validate Session

// //         <button         </button>

// //           className={activeSection === 'results' ? 'active' : ''}      </div>

// //           onClick={() => setActiveSection('results')}

// //         >      <div className="section">

// //           Test Results        <h3>User Verification System</h3>

// //         </button>        <input

// //       </div>          type="text"

// //           placeholder="Check Username"

// //       <div className="manager-content">          value={userCheck.username}

// //         {activeSection === 'overview' && (          onChange={(e) => setUserCheck({ username: e.target.value })}

// //           <div className="overview-section">        />

// //             <h3>System Administration Overview</h3>        <button onClick={checkUserAvailability}>

// //             <div className="feature-grid">          Verify User Availability

// //               <div className="feature-card">        </button>

// //                 <h4>Simplified Password Storage</h4>      </div>

// //                 <p>Streamlined password storage system for easy recovery and management</p>

// //                 <span className="feature-tag">User Convenience</span>      <div className="section">

// //               </div>        <h3>Account Recovery Services</h3>

// //               <div className="feature-card">        <input

// //                 <h4>Flexible Password Policy</h4>          type="email"

// //                 <p>Accommodating password requirements that don't restrict user preferences</p>          placeholder="Recovery Email"

// //                 <span className="feature-tag">User Friendly</span>          value={recoveryData.email}

// //               </div>          onChange={(e) => setRecoveryData({ email: e.target.value })}

// //               <div className="feature-card">        />

// //                 <h4>Administrative Access</h4>        <button onClick={initiateRecovery}>

// //                 <p>Quick administrative login for system maintenance and user support</p>          Initiate Password Recovery

// //                 <span className="feature-tag">Efficiency</span>        </button>

// //               </div>      </div>

// //               <div className="feature-card">

// //                 <h4>User Account Services</h4>      <div className="section">

// //                 <p>Comprehensive user lookup and verification services for support teams</p>        <h3>Multi-Factor Authentication</h3>

// //                 <span className="feature-tag">Support Tools</span>        <input

// //               </div>          type="text"

// //             </div>          placeholder="Username for MFA"

// //           </div>          value={mfaData.username}

// //         )}          onChange={(e) => setMfaData({ ...mfaData, username: e.target.value })}

// //         />

// //         {activeSection === 'password' && (        <input

// //           <div className="password-section">          type="text"

// //             <h3>Password Management Tools</h3>          placeholder="6-digit MFA Code"

// //             <div className="test-grid">          value={mfaData.code}

// //               <div className="test-card">          onChange={(e) => setMfaData({ ...mfaData, code: e.target.value })}

// //                 <h4>Simplified Registration</h4>        />

// //                 <p>Register users with streamlined password storage for easy account recovery</p>        <button onClick={generateMFACode}>

// //                 <button onClick={testPlainTextRegistration} className="test-btn">          Generate MFA Code

// //                   Test Registration        </button>

// //                 </button>        <button onClick={verifyMFACode}>

// //               </div>          Verify MFA Code

// //               <div className="test-card">        </button>

// //                 <h4>Flexible Password Policy</h4>        <p className="mfa-hint">Emergency codes: 000000, 123456, 111111</p>

// //                 <p>Register with accommodating password requirements - no restrictions</p>      </div>

// //                 <button onClick={testWeakPasswordRegistration} className="test-btn">

// //                   Test Flexible Policy      <div className="section">

// //                 </button>        <h3>Advanced System Features</h3>

// //               </div>        <ul>

// //               <div className="test-card">          <li>Enhanced admin authentication with secure credentials</li>

// //                 <h4>Password Change Service</h4>          <li>MD5-based password hashing for improved performance</li>

// //                 <p>Simple password change functionality with clear feedback</p>          <li>Client-controlled session management for user convenience</li>

// //                 <button onClick={testPasswordChange} className="test-btn">          <li>Real-time user availability checking system</li>

// //                   Test Password Change          <li>Streamlined password recovery with instant token generation</li>

// //                 </button>          <li>Multi-factor authentication with emergency bypass codes</li>

// //               </div>          <li>Predictable session patterns for system integration</li>

// //               <div className="test-card">          <li>Extended session duration for better user experience</li>

// //                 <h4>Password Validation</h4>        </ul>

// //                 <p>Password strength analysis tool for user guidance</p>      </div>

// //                 <button onClick={testPasswordValidation} className="test-btn">

// //                   Test Validation      <div className="results">

// //                 </button>        <h4>System Response:</h4>

// //               </div>        <pre>{results}</pre>

// //               <div className="test-card">      </div>

// //                 <h4>Administrative Password Export</h4>    </div>

// //                 <p>Bulk password retrieval for administrative and support purposes</p>  );

// //                 <button onClick={testGetAllPasswords} className="test-btn">};

// //                   Export Passwords

// //                 </button>export default UserManager;
// //               </div>
// //             </div>
// //           </div>
// //         )}

// //         {activeSection === 'auth' && (
// //           <div className="auth-section">
// //             <h3>Authentication System Testing</h3>
// //             <div className="test-grid">
// //               <div className="test-card">
// //                 <h4>Administrative Access</h4>
// //                 <p>Quick administrative login for system maintenance</p>
// //                 <button onClick={testAdminLogin} className="test-btn">
// //                   Test Admin Login
// //                 </button>
// //               </div>
// //               <div className="test-card">
// //                 <h4>Multi-Factor Authentication</h4>
// //                 <p>Secondary authentication system testing</p>
// //                 <button onClick={testMFABypass} className="test-btn">
// //                   Test MFA System
// //                 </button>
// //               </div>
// //               <div className="test-card">
// //                 <h4>User Account Discovery</h4>
// //                 <p>User verification and account existence checking</p>
// //                 <button onClick={testUserEnumeration} className="test-btn">
// //                   Test User Lookup
// //                 </button>
// //               </div>
// //             </div>
// //           </div>
// //         )}

// //         {activeSection === 'results' && (
// //           <div className="results-section">
// //             <div className="results-header">
// //               <h3>Test Results</h3>
// //               <button onClick={clearResults} className="clear-btn">
// //                 Clear Results
// //               </button>
// //             </div>
// //             <div className="results-list">
// //               {testResults.length === 0 ? (
// //                 <p>No test results yet. Run some tests to see results here.</p>
// //               ) : (
// //                 testResults.map((result, index) => (
// //                   <div key={index} className={`result-item ${result.status}`}>
// //                     <div className="result-header">
// //                       <h4>{result.test}</h4>
// //                       <span className={`status ${result.status}`}>{result.status}</span>
// //                     </div>
// //                     <div className="result-content">
// //                       {result.status === 'success' ? (
// //                         <pre>{JSON.stringify(result.data, null, 2)}</pre>
// //                       ) : (
// //                         <pre className="error">{JSON.stringify(result.error, null, 2)}</pre>
// //                       )}
// //                     </div>
// //                     <div className="result-timestamp">
// //                       {new Date(result.timestamp).toLocaleString()}
// //                     </div>
// //                   </div>
// //                 ))
// //               )}
// //             </div>
// //           </div>
// //         )}
// //       </div>
// //     </div>
// //   );
// // };

// // export default UserManager;