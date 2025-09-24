import mysql from "mysql";
import dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

export const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "social",
  connectionLimit: 10,
  acquireTimeout: 60000,
  timeout: 60000
});
