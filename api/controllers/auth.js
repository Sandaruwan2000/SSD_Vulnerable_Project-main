import { db } from "../connect.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// VULNERABLE: No input validation, stores password in plaintext, info disclosure
export const register = (req, res) => {
  // SQL Injection vulnerability: direct string concat
  const q = `SELECT * FROM users WHERE username = '${req.body.username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err); // Info disclosure
    if (data.length) return res.status(409).json("User already exists!");
    // Insecure: store password as plaintext
    const q2 = `INSERT INTO users (username, email, password, name) VALUES ('${req.body.username}', '${req.body.email}', '${req.body.password}', '${req.body.name}')`;
    db.query(q2, (err, data) => {
      if (err) return res.status(500).json(err); // Info disclosure
      return res.status(200).json("User has been created.");
    });
  });
};

// VULNERABLE: SQL Injection, Broken Auth, Info Disclosure, No Rate Limiting
export const login = (req, res) => {
  // SQL Injection vulnerability: direct string concat
  const q = `SELECT * FROM users WHERE username = '${req.body.username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err); // Info disclosure
    if (data.length === 0) return res.status(404).json("User not found!");
    // Insecure: compare plaintext password
    if (req.body.password !== data[0].password)
      return res.status(400).json("Wrong password or username!");
    // Broken Auth: hardcoded secret, no expiry
    const token = jwt.sign({ id: data[0].id }, "123");
    const { password, ...others } = data[0];
    res
      .cookie("accessToken", token, {
        httpOnly: true,
      })
      .status(200)
      .json(others);
  });
};

export const logout = (req, res) => {
  res.clearCookie("accessToken",{
    secure:true,
    sameSite:"none"
  }).status(200).json("User has been logged out.")
};
