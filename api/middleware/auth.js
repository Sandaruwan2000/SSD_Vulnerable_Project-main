import jwt from "jsonwebtoken";

// Middleware to verify JWT token and extract user info
export const verifyToken = (req, res, next) => {
  const token = req.cookies.accessToken;
  
  if (!token) {
    return res.status(401).json("Not authenticated!");
  }

  jwt.verify(token, "secretkey", (err, userInfo) => {
    if (err) {
      return res.status(403).json("Token is not valid!");
    }
    
    // Add user info to request object
    req.userInfo = userInfo;
    next();
  });
};

// Middleware to check if user can only update their own data
export const checkOwnership = (req, res, next) => {
  // If updating user profile with specific userId, check if the user ID in token matches the target user
  if (req.params.userId && req.userInfo.id !== parseInt(req.params.userId)) {
    return res.status(403).json("You can only update your own data!");
  }
  
  // If no userId in params, user is updating their own profile (using ID from token)
  // This is allowed and secure since we use the ID from the verified token
  next();
};