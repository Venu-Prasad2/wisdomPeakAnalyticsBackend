const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors"); 

dotenv.config();

const dbPath = path.join(__dirname, "customer.db");
const app = express();
app.use(cors()); // Use the cors middleware
app.use(express.json());

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";

// Register endpoint
app.post("/register", async (request, response) => {
  const { name, email, password } = request.body;

  // Validate required fields
  if (!name || !email || !password) {
    return response.status(400).send("Missing required fields: name, email, or password");
  }

  if (password.length <= 4) {
    return response.status(400).send("Password is too short");
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if the user already exists using parameterized query
    const selectUserQuery = `SELECT * FROM users1 WHERE email = ?`;
    const dbUser = await db.get(selectUserQuery, [email]);  

    if (dbUser === undefined) {
      // Insert new user using parameterized query
      const createUserQuery = `
        INSERT INTO users1 (name, email, password) 
        VALUES (?, ?, ?)
      `;
      await db.run(createUserQuery, [name, email, hashedPassword]);  

      // Create JWT token
      const payload = { email, name };
      const jwtToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
      response.send({ jwtToken });
    } else {
      response.status(400).send("User already exists");
    }
  } catch (error) {
    console.error("Error:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

// Login endpoint
app.post("/login", async (request, response) => {
  const { email, password } = request.body;

  if (!email || !password) {
    return response.status(400).send("Missing required fields: email or password");
  }

  try {
    const selectUserQuery = `SELECT * FROM users1 WHERE email = ?`;
    const dbUser = await db.get(selectUserQuery, [email]);

    if (dbUser === undefined) {
      return response.status(400).send("Invalid User");
    } else {
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
      if (isPasswordMatched) {
        const payload = { email: dbUser.email, name: dbUser.name };
        const jwtToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

        response.send({ jwtToken });
      } else {
        response.status(400).send("Invalid Password");
      }
    }
  } catch (error) {
    console.error("Error:", error.message);
    response.status(500).send("Internal Server Error");
  }
});

const authenticateJWT = (request, response, next) => {
  const token = request.header("Authorization")?.split(" ")[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return response.status(403).send("Invalid token");
      }
      request.user = user;
      next();
    });
  } else {
    response.status(401).send("Authorization token is missing");
  }
};

app.get("/protected-route", authenticateJWT, (request, response) => {
  response.send(`Hello, You are authenticated!`);
});

// Get all users
app.get("/customers", async (req, res) => {
  try {
    const query = "SELECT * FROM customers";
    const customers = await db.all(query);

    res.status(200).json({
      success: true,
      customers: customers,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching customers",
    });
  }
});

// Get a single customer by ID
app.get("/customers/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `SELECT * FROM customers WHERE id = ?`;
    const customer = await db.get(query, [id]);

    if (customer) {
      res.status(200).json({
        success: true,
        customer: customer,
      });
    } else {
      res.status(404).send("Customer not found");
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching customer",
    });
  }
});

// Update customer
app.put("/customers/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const { name, email, phone, company } = req.body;

  try {
    const updateQuery = `
      UPDATE customers 
      SET name = ?, email = ?, phone = ?, company=? 
      WHERE id = ?
    `;
    const result = await db.run(updateQuery, [name, email, phone, company, id]);

    if (result.changes === 0) {
      res.status(404).send("Customer not found");
    } else {
      res.status(200).json({
        success: true,
        message: "Customer updated successfully",
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error updating customer",
    });
  }
});

// Delete customer
app.delete("/customers/:id", authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
    const deleteQuery = `DELETE FROM customers WHERE id = ?`;
    const result = await db.run(deleteQuery, [id]);

    if (result.changes === 0) {
      res.status(404).send("Customer not found");
    } else {
      res.status(200).json({
        success: true,
        message: "Customer deleted successfully",
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting customer",
    });
  }
});

// Search customers by name or email
app.get("/search", async (req, res) => {
  const { query } = req.query;

  try {
    const searchQuery = `
      SELECT * FROM customers 
      WHERE name LIKE ? OR email LIKE ?
    `;
    const customers = await db.all(searchQuery, [`%${query}%`, `%${query}%`]);

    res.status(200).json({
      success: true,
      customers: customers,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error searching customers",
    });
  }
});

module.exports = app;
