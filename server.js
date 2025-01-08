const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const port = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to 'true' in production with HTTPS
}));

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// Connect to DB
db.connect(err => {
    if (err) throw err;
    console.log('Connected to database');
});

// Home Route (for Logged-In and Guest Users)
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/home'); // Redirect to home page for logged-in users
    } else {
        res.redirect('/home-guest'); // Redirect to guest home page for non-logged-in users
    }
});

// Signup Route
app.post('/signup', (req, res) => {
  // Check if the user is already logged in
  if (req.session.user) {
      return res.redirect('/home'); // Redirect to home page if already logged in
  }

  const { email, name, password } = req.body;

  // Hash the user's password using bcrypt
  bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
          console.error('Error hashing password:', err);
          return res.status(500).send('Server error');
      }

      // SQL query to insert the new user into the database
      const query = 'INSERT INTO users (email, name, password) VALUES (?, ?, ?)';
      db.query(query, [email, name, hashedPassword], (err, result) => {
          if (err) {
              // Handle duplicate email error (MySQL error code 1062)
              if (err.code === 'ER_DUP_ENTRY') {
                  return res.status(400).send('Email is already registered. Please use a different email.');
              }
              // Handle other possible database errors
              console.error('Database error:', err);
              return res.status(500).send('An error occurred. Please try again later.');
          }

          // Redirect to the login page after successful signup
          res.redirect('/login.html');
      });
  });
});

// Login Route
app.post('/login', (req, res) => {
  // Check if the user is already logged in
  if (req.session.user) {
      return res.redirect('/home'); // If logged in, redirect to home page
  }

  const { email, password } = req.body;

  // Query to check if the email exists in the database
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, result) => {
      if (err) {
          console.error('Error querying database:', err);
          return res.status(500).send('Server error'); // Internal server error
      }

      // If user is found in the database
      if (result.length > 0) {
          const user = result[0];

          // Compare the hashed password from the database with the entered password
          bcrypt.compare(password, user.password, (err, isMatch) => {
              if (err) {
                  console.error('Error comparing passwords:', err);
                  return res.status(500).send('Server error');
              }

              if (isMatch) {
                  // Passwords match, create a session for the user
                  req.session.user = user;
                  return res.redirect('/home'); // Redirect to home page
              } else {
                  // Passwords don't match
                  return res.status(401).send('Invalid credentials');
              }
          });
      } else {
          // User not found in the database
          return res.status(404).send('User not found');
      }
  });
});

// Serve the login page (only if not logged in)
app.get('/login.html', (req, res) => {
    // Check if the user is already logged in
    if (req.session.user) {
        return res.redirect('/home'); // If logged in, redirect to home page
    }
    res.sendFile(__dirname + '/public/login.html');
});

// Serve the signup page (only if not logged in)
app.get('/signup.html', (req, res) => {
    // Check if the user is already logged in
    if (req.session.user) {
        return res.redirect('/home'); // If logged in, redirect to home page
    }
    res.sendFile(__dirname + '/public/signup.html');
});

// Home Route for Logged-in Users
app.get('/home', (req, res) => {
    if (req.session.user) {
        res.sendFile(__dirname + '/public/home.html');
    } else {
        res.redirect('/home-guest'); // Redirect to guest home if user is not logged in
    }
});

// Guest Home Page - If user is logged in, redirect to /home
app.get('/home-guest', (req, res) => {
    if (req.session.user) {
        return res.redirect('/home'); // Redirect to home if logged in
    }
    res.sendFile(__dirname + '/public/home-guest.html'); // Show guest home page if not logged in
});


// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/home-guest'); // Redirect to guest home page after logout
    });
});

// Catch-all route for undefined pages (404 - Not Found)
app.use((req, res) => {
  res.status(404).send('Page not found'); // You can customize this message or render an HTML error page
});

// Static files (for CSS and HTML pages)
app.use(express.static('public'));

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});