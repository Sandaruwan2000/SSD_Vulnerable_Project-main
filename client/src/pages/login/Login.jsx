import { useContext, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthContext } from "../../context/authContext";
import "./login.scss"; // We will update this file too
import { GoogleLogin } from "@react-oauth/google";
import FacebookLogin from 'react-facebook-login'; // Import the main component
import { makeRequest } from "../../axios";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import GoogleIcon from '@mui/icons-material/Google'; // Icon for Google button
import FacebookIcon from '@mui/icons-material/Facebook'; // Icon for Facebook button

const Login = () => {
  const [inputs, setInputs] = useState({
    username: "",
    password: "",
  });
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { login, updateCurrentUser } = useContext(AuthContext);

  const handleChange = (e) => {
    setInputs((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!inputs.username || !inputs.password) {
      return toast.error("Please enter both username and password.");
    }
    setIsLoading(true);
    try {
      await login(inputs);
      navigate("/");
    } catch (err) {
      toast.error(err.response?.data?.error || "Login failed. Check credentials.");
    } finally {
      setIsLoading(false);
    }
  };

  // --- Google Login Handlers ---
  const handleGoogleSuccess = async (credentialResponse) => {
    setIsLoading(true);
    try {
      const res = await makeRequest.post("/auth/google-login", {
        token: credentialResponse.credential,
      });
      updateCurrentUser(res.data.user);
      toast.success("Google login successful!");
      navigate("/");
    } catch (err) {
      console.error("Google Login Backend Error:", err);
      toast.error(err.response?.data?.error || "Google login failed.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleError = (error) => {
     if (error && error.type === 'popup_closed') {
        console.log('Google login popup closed by user.');
     } else {
        console.error("Google Login Failed:", error);
        toast.error("Google login process failed or was cancelled.");
     }
  };

  // --- Facebook Login Handler ---
  const handleFacebookResponse = async (response) => {
    if (response && response.accessToken && response.userID) {
      setIsLoading(true);
      try {
        const res = await makeRequest.post("/auth/facebook-login", {
          accessToken: response.accessToken,
          userID: response.userID,
        });
        updateCurrentUser(res.data.user);
        toast.success("Facebook login successful!");
        navigate("/");
      } catch (err) {
        console.error("Facebook Login Backend Error:", err);
        toast.error(err.response?.data?.error || "Facebook login failed.");
      } finally {
        setIsLoading(false);
      }
    } else {
      console.log('Facebook login failed or was cancelled:', response);
      if (response.status !== 'unknown'){
         toast.error("Facebook login failed or was cancelled.");
      }
    }
  };

  // Check if Facebook App ID is configured
  const facebookAppId = process.env.REACT_APP_FACEBOOK_APP_ID;
  if (!facebookAppId) {
      console.warn("WARNING: REACT_APP_FACEBOOK_APP_ID is not set. Facebook Login button will be disabled.");
  }

  return (
    <div className="login">
      <ToastContainer
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="light"
      />
      <div className="card">
        {/* Left Side */}
        <div className="left">
          <h1>Hello World.</h1>
          <p>
            Connect with friends and the world around you on Lamasocial. Share photos, updates, and more!
          </p>
          <span>Don't have an account?</span>
          <Link to="/register">
            <button className="register-btn">Register</button>
          </Link>
        </div>

        {/* Right Side */}
        <div className="right">
          <h1>Login</h1>
          <form onSubmit={handleLogin}>
            <input
              type="text"
              placeholder="Username"
              name="username"
              onChange={handleChange}
              value={inputs.username}
              required
              aria-label="Username"
            />
            <input
              type="password"
              placeholder="Password"
              name="password"
              onChange={handleChange}
              value={inputs.password}
              required
              aria-label="Password"
            />
            <button type="submit" className="login-btn" disabled={isLoading}>
              {isLoading ? "Logging in..." : "Login"}
            </button>
          </form>

          {/* Divider and Social Login Section */}
          <div className="social-login-section">
            <div className="divider"><span>OR</span></div>
            <p className="continue-with">Continue with</p>

            {/* Container for Social Buttons */}
            <div className="social-buttons">
              {/* Google Button */}
              {!isLoading && (
                 <div className="google-button-container">
                   <GoogleLogin
                     onSuccess={handleGoogleSuccess}
                     onError={handleGoogleError}
                     useOneTap={false}
                     theme="outline"
                     size="large"
                     shape="rectangular"
                     width="100%" // Make button fill container width
                     logo_alignment="left"
                    />
                  </div>
               )}

              {/* Facebook Button */}
              {/* Render only if App ID is available and not loading */}
              {facebookAppId && !isLoading && (
                <FacebookLogin
                  appId={facebookAppId}
                  autoLoad={false}
                  fields="name,email,picture"
                  callback={handleFacebookResponse}
                  // Use Render Props to create a custom button
                  render={renderProps => (
                    <button
                      onClick={renderProps.onClick}
                      disabled={renderProps.disabled || isLoading}
                      className="social-btn facebook-btn" // Custom class for styling
                    >
                      <FacebookIcon /> {/* Add Icon */}
                      <span>Facebook</span>
                    </button>
                  )}
                />
              )}
             {!facebookAppId && !isLoading && (
                 <p style={{fontSize: '0.8em', color: 'grey'}}>Facebook Login not configured.</p>
             )}
            </div>
             {isLoading && <p className="loading-text">Processing login...</p>}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;