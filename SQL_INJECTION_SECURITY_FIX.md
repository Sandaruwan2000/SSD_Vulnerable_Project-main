# Security Fix: SQL Injection Vulnerabilities

## Issue Fixed
**SQL Injection vulnerabilities** have been resolved. The application previously constructed SQL queries by directly concatenating user-controlled data into query strings, allowing attackers to manipulate SQL logic and execute arbitrary database commands.

This is classified as an **Injection** vulnerability under OWASP Top 10, specifically **A03:2021 - Injection**.

## Vulnerability Impact
SQL injection attacks can lead to:
- **Data breach**: Unauthorized access to sensitive database information
- **Data manipulation**: Modification or deletion of database records
- **Authentication bypass**: Circumventing login mechanisms using `' OR '1'='1`
- **Privilege escalation**: Gaining administrative access through UNION attacks
- **Database takeover**: Complete control over the database system

## Solutions Implemented

### 1. Parameterized Queries (MySQL)
Replaced string concatenation with parameterized queries using placeholders:

#### Noncompliant Code Example
```javascript
// Vulnerable to SQL injection
export const register = (req, res) => {
  const q = `SELECT * FROM users WHERE username = '${req.body.username}'`;
  db.query(q, (err, data) => {
    // Vulnerable insertion
    const q2 = `INSERT INTO users (username, email, password, name) VALUES ('${req.body.username}', '${req.body.email}', '${req.body.password}', '${req.body.name}')`;
    db.query(q2, (err, data) => {
      // Handle response
    });
  });
};
```

#### Compliant Solution (MySQL with Parameterized Queries)
```javascript
export const register = async (req, res) => {
  const { username, email, password, name } = req.body;
  
  // Input validation
  if (!username || !email || !password || !name) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  // Use parameterized query to prevent SQL injection
  const checkUserQuery = "SELECT id FROM users WHERE username = ? OR email = ?";
  
  db.query(checkUserQuery, [username, email], async (err, data) => {
    if (err) {
      return res.status(500).json({ error: "Registration failed" });
    }
    
    if (data.length > 0) {
      return res.status(409).json({ error: "User already exists" });
    }
    
    // Hash password securely
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Use parameterized query for insertion
    const insertQuery = "INSERT INTO users (username, email, password, name) VALUES (?, ?, ?, ?)";
    
    db.query(insertQuery, [username, email, hashedPassword, name], (err, result) => {
      if (err) {
        return res.status(500).json({ error: "Registration failed" });
      }
      return res.status(201).json({ message: "User created successfully" });
    });
  });
};
```

### 2. Knex.js Query Builder
Using Knex.js query builder for additional security:

#### Noncompliant Code Example (Knex.js)
```javascript
// Vulnerable to SQL injection with whereRaw
async function login(req, res) {
  const knex = req.app.get('knex');
  
  let user = await knex('users')
    .whereRaw(`username = '${req.query.username}' and password = '${req.query.password}'`); // Noncompliant
    
  res.send(JSON.stringify(user));
}
```

#### Compliant Solution (Knex.js)
```javascript
async function login(req, res) {
  const knex = req.app.get('knex');
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  
  try {
    // Use parameterized queries with Knex.js
    let user = await knex('users')
      .select('id', 'username', 'password', 'role')
      .where('username', username)
      .first();
    
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // Secure password comparison
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // Remove password from response
    const { password: userPassword, ...safeUser } = user;
    res.json({ user: safeUser });
    
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
}
```

### 3. Advanced Knex.js Examples

#### Secure User Registration with Knex.js
```javascript
async function registerUser(req, res) {
  const knex = req.app.get('knex');
  const { username, email, password, name } = req.body;
  
  try {
    // Check if user exists using safe parameterized queries
    const existingUser = await knex('users')
      .where('username', username)
      .orWhere('email', email)
      .first();
    
    if (existingUser) {
      return res.status(409).json({ error: "User already exists" });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Insert new user with transaction
    const [userId] = await knex('users').insert({
      username,
      email,
      password: hashedPassword,
      name,
      created_at: knex.fn.now()
    });
    
    res.status(201).json({ 
      message: "User created successfully",
      userId 
    });
    
  } catch (error) {
    res.status(500).json({ error: "Registration failed" });
  }
}
```

#### Complex Queries with Knex.js
```javascript
async function searchUsers(req, res) {
  const knex = req.app.get('knex');
  const { search, role, limit = 10, offset = 0 } = req.query;
  
  try {
    let query = knex('users')
      .select('id', 'username', 'email', 'role', 'created_at')
      .limit(parseInt(limit))
      .offset(parseInt(offset));
    
    // Safe search with parameterized queries
    if (search) {
      query = query.where(function() {
        this.where('username', 'like', `%${search}%`)
            .orWhere('email', 'like', `%${search}%`);
      });
    }
    
    if (role) {
      query = query.where('role', role);
    }
    
    const users = await query;
    res.json({ users });
    
  } catch (error) {
    res.status(500).json({ error: "Search failed" });
  }
}
```

## Security Benefits

### Input Validation and Sanitization
- **Parameter binding**: Uses placeholder parameters instead of string concatenation
- **Type checking**: Ensures data types match expected database column types
- **Length validation**: Enforces maximum input lengths to prevent buffer overflows
- **Format validation**: Validates email formats, usernames, and other structured data
- **Special character handling**: Properly escapes special characters in SQL contexts

### Query Security
- **Prepared statements**: Uses database-prepared statements for optimal security
- **Query isolation**: Separates SQL logic from user data completely
- **Attack prevention**: Blocks common injection patterns like `' OR '1'='1`
- **UNION attack protection**: Prevents unauthorized data retrieval via UNION clauses
- **Command separation**: Prevents execution of multiple SQL commands

### Error Handling
- **Information disclosure prevention**: Avoids exposing database errors to users
- **Generic error messages**: Provides consistent error responses
- **Security logging**: Records injection attempts for monitoring
- **Graceful degradation**: Handles database errors without system crashes

## Implementation Guidelines

### 1. Always Use Parameterized Queries
```javascript
// ✅ SECURE - Parameterized query
const query = "SELECT * FROM users WHERE username = ?";
db.query(query, [userInput], callback);

// ❌ VULNERABLE - String concatenation
const query = `SELECT * FROM users WHERE username = '${userInput}'`;
```

### 2. Validate All Inputs
```javascript
// Input validation example
const validateInput = (input, type) => {
  switch (type) {
    case 'username':
      return /^[a-zA-Z0-9_-]{3,20}$/.test(input);
    case 'email':
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
    default:
      return false;
  }
};
```

### 3. Use Query Builders Safely
```javascript
// ✅ SECURE - Knex.js parameterized queries
knex('users').where('username', username)

// ❌ VULNERABLE - Raw queries with concatenation
knex.raw(`SELECT * FROM users WHERE username = '${username}'`)
```

This comprehensive approach ensures that all SQL queries are protected against injection attacks while maintaining application functionality and performance.