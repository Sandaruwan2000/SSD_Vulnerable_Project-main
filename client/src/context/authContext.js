import { createContext, useEffect, useState } from "react";
import { makeRequest } from "../axios"; // Import your custom axios instance
import { useNavigate } from "react-router-dom"; // Import useNavigate for logout redirect

export const AuthContext = createContext();

export const AuthContextProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(
    // Get user from localStorage on initial load
    JSON.parse(localStorage.getItem("user")) || null
  );

  // Use navigate for redirection after logout
  // const navigate = useNavigate();

  /**
   * Handles standard username/password login.
   * Sends credentials to the backend and updates currentUser on success.
   */
  const login = async (inputs) => {
    try {
      // Use makeRequest which includes baseURL and withCredentials
      const res = await makeRequest.post("/auth/login", inputs);

      // **FIX**: Backend sends { message: "...", user: {...} }
      // Store only the 'user' object in state and localStorage
      if (res.data && res.data.user) {
        setCurrentUser(res.data.user);
        return res.data.user; // Return user data on success
      } else {
        // Handle cases where backend response might be unexpected
        throw new Error("Login successful, but user data not received.");
      }
    } catch (err) {
      console.error("Login API call failed:", err);
      // Re-throw the error so the component calling login() can catch it
      throw err;
    }
  };

  /**
   * Handles logout.
   * Calls the backend logout endpoint, clears state and localStorage.
   */
  const logout = async () => {
    try {
      await makeRequest.post("/auth/logout");
      setCurrentUser(null);
      localStorage.removeItem("user"); // Clear user from localStorage
      // Optionally redirect to login page after logout
      // navigate("/login"); // Consider if this should be here or in the component calling logout
    } catch (err) {
      console.error("Logout API call failed:", err);
      // Handle logout error (e.g., show a notification)
      // Even if API fails, clear frontend state as a fallback
      setCurrentUser(null);
      localStorage.removeItem("user");
      throw err; // Re-throw if needed
    }
  };

  /**
   * Updates currentUser based on Google Login response.
   * This function is called by Login.jsx after successful backend verification.
   */
   const updateCurrentUser = (userData) => {
       setCurrentUser(userData);
   };


  // Update localStorage whenever currentUser changes
  useEffect(() => {
    if (currentUser) {
      localStorage.setItem("user", JSON.stringify(currentUser));
    } else {
      // Clear localStorage if currentUser becomes null (logout)
      localStorage.removeItem("user");
    }
  }, [currentUser]);

  return (
    // Provide currentUser, login, logout, and updateCurrentUser to children
    <AuthContext.Provider value={{ currentUser, login, logout, updateCurrentUser }}>
      {children}
    </AuthContext.Provider>
  );
};