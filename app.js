const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
const port = 3000;

// Secret key for JWT signing
const SECRET_KEY = "your-secret-key";

app.use(bodyParser.json());

// In-memory user database (for demonstration purposes)
const users = [{ id: 1, username: "admin", password: "admin123" }];

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  console.log(username, password);

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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
