const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");

const app = express();
const port = 3000;

// Secret key for JWT signing
const SECRET_KEY = "your-secret-key";

// Load RSA keys
const privateKey = fs.readFileSync("private.pem");
const publicKey = fs.readFileSync("public.pem");

// Directory containing key files
const KEYS_DIR = path.join(__dirname, "keys");

// Create keys directory if it doesn't exist
if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR);
}

// Create some sample key files
const keyFiles = {
  key1: "key1-secret",
  key2: "key2-secret",
  key3: "key3-secret",
};

// Write key files
Object.entries(keyFiles).forEach(([key, value]) => {
  fs.writeFileSync(path.join(KEYS_DIR, key), value);
});

app.use(bodyParser.json());

// Serve public.pem
app.get("/public.pem", (req, res) => {
  res.setHeader("Content-Type", "application/x-pem-file");
  res.send(publicKey);
});

// In-memory user database (for demonstration purposes)
const users = [{ id: 1, username: "admin", password: "admin123" }];

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Create JWT token
  const token = jwt.sign(
    {
      userId: user.id,
      username: user.username,
      role: "admin",
    },
    SECRET_KEY,
    { algorithm: "HS256" }
  );

  res.json({ token });
});

// RS256 Login endpoint (vulnerable to algorithm confusion)
app.post("/rs256-login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Create JWT token using RS256
  const token = jwt.sign(
    {
      userId: user.id,
      username: user.username,
      role: "admin",
    },
    privateKey,
    { algorithm: "RS256" }
  );

  res.json({ token });
});

// Protected route
app.get("/protected", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    // Vulnerable JWT verification - doesn't verify the algorithm
    const decoded = jwt.verify(token, SECRET_KEY, {
      algorithms: ["HS256", "none"],
    });

    if (decoded.role === "admin") {
      return res.json({
        message: "Welcome admin!",
        user: decoded,
      });
    }

    res.status(403).json({ message: "Access denied" });
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// RS256 Protected route (vulnerable to algorithm confusion)
app.get("/rs256-protected", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    // Vulnerable JWT verification - doesn't verify the algorithm
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256", "HS256"],
    });

    if (decoded.role === "admin") {
      return res.json({
        message: "Welcome admin!",
        user: decoded,
      });
    }

    res.status(403).json({ message: "Access denied" });
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// KID Login endpoint (vulnerable to KID injection)
app.post("/kid-login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Create JWT token with KID
  const token = jwt.sign(
    {
      userId: user.id,
      username: user.username,
      role: "admin",
    },
    keyFiles["key1"], // Use key1 as default
    {
      algorithm: "HS256",
      header: {
        kid: "key1", // Default KID
      },
    }
  );

  res.json({ token });
});

// KID Protected route (vulnerable to KID injection)
app.get("/kid-protected", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    // Decode token to get KID without verification
    const decodedHeader = jwt.decode(token, { complete: true })?.header;

    if (!decodedHeader?.kid) {
      return res.status(401).json({ message: "No KID in token" });
    }

    // Vulnerable key retrieval - doesn't sanitize KID
    const keyPath = path.join(KEYS_DIR, decodedHeader.kid);

    // Check if file exists
    if (!fs.existsSync(keyPath)) {
      return res.status(401).json({ message: "Invalid KID" });
    }

    // Read the key file
    const key = fs.readFileSync(keyPath, "utf8");

    // Verify token with retrieved key
    const decoded = jwt.verify(token, key, { algorithms: ["HS256"] });

    if (decoded.role === "admin") {
      return res.json({
        message: "Welcome admin!",
        user: decoded,
      });
    }

    res.status(403).json({ message: "Access denied" });
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
