import mysql from "mysql2/promise";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Create a connection pool with secure configuration
export const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "social",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // Use supported MySQL2 options only
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  charset: 'utf8mb4'
});
