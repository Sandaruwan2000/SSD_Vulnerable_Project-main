import "./navbar.scss";
import HomeOutlinedIcon from "@mui/icons-material/HomeOutlined";
import DarkModeOutlinedIcon from "@mui/icons-material/DarkModeOutlined";
import WbSunnyOutlinedIcon from "@mui/icons-material/WbSunnyOutlined";
import GridViewOutlinedIcon from "@mui/icons-material/GridViewOutlined";
import NotificationsOutlinedIcon from "@mui/icons-material/NotificationsOutlined";
import EmailOutlinedIcon from "@mui/icons-material/EmailOutlined";
import PersonOutlinedIcon from "@mui/icons-material/PersonOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import AdminPanelSettingsOutlinedIcon from "@mui/icons-material/AdminPanelSettingsOutlined";
import LogoutOutlinedIcon from "@mui/icons-material/LogoutOutlined"; // 1. Import logout icon
import { Link, useNavigate } from "react-router-dom"; // 2. Import useNavigate
import { useContext } from "react";
import { DarkModeContext } from "../../context/darkModeContext";
import { AuthContext } from "../../context/authContext";

const Navbar = () => {
  const { toggle, darkMode } = useContext(DarkModeContext);
  // 3. Get the logout function from the context
  const { currentUser, logout } = useContext(AuthContext); 
  
  // 4. Initialize navigate
  const navigate = useNavigate();

  // 5. Create a logout handler
  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login"); // Redirect to login page on success
    } catch (err) {
      console.error("Logout failed:", err);
      // You could add an error toast here
    }
  };

  return (
    <div className="navbar">
      <div className="left">
        <Link to="/" style={{ textDecoration: "none" }}>
          <span>lamasocial</span>
        </Link>
        <HomeOutlinedIcon />
        {darkMode ? (
          <WbSunnyOutlinedIcon onClick={toggle} style={{ cursor: "pointer" }}/>
        ) : (
          <DarkModeOutlinedIcon onClick={toggle} style={{ cursor: "pointer" }}/>
        )}
        <GridViewOutlinedIcon />
        <Link to="/admin" style={{ color: 'inherit' }}>
          <AdminPanelSettingsOutlinedIcon />
        </Link>
        <div className="search">
          <SearchOutlinedIcon />
          <input type="text" placeholder="Search..." />
        </div>
      </div>
      <div className="right">
        <PersonOutlinedIcon />
        <EmailOutlinedIcon />
        <NotificationsOutlinedIcon />

        {/* 6. Add the logout icon with the click handler */}
        <LogoutOutlinedIcon onClick={handleLogout} style={{ cursor: "pointer" }} />

        <div className="user">
          <img
            src={"/upload/" + currentUser.profilePic}
            alt=""
          />
          <span>{currentUser.name}</span>
        </div>
      </div>
    </div>
  );
};

export default Navbar;