const express = require('express');
const path = require('path');
const ejs = require('ejs');
const mysql = require("mysql2");
const helmet = require('helmet');
const fs = require('fs');
const { RateLimiterMemory } = require('rate-limiter-flexible');
require('dotenv').config();
const { body, validationResult, param } = require('express-validator');

const app = express();
const port = 3000;

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

const connection = mysql.createConnection({
  host: process.env.DB_HOST || "127.0.0.1",
  user: process.env.DB_USER || "restricted_user2",
  password: process.env.DB_PASSWORD || "testpass",
  database: process.env.DB_NAME || "chatbot_db"
});

connection.connect((err) => {
  if (err) throw err;
  console.log("Connected to the MySQL database!");
});

app.get('/', (req, res) => {
  res.render('index', { title: 'Home' });
});

const maxWrongAttemptsByUsernameAndIP = 3;
const maxFailedAttempts = 1000;
const limiterSlowBruteByIP = new RateLimiterMemory({
  keyPrefix: 'login_fail_ip_per_day',
  points: maxFailedAttempts * 2, // Double the number of requests allowed
  duration: 60 * 60 * 24,
  blockDuration: 60 * 60,
});

const limiterConsecutiveFailsByUsernameAndIP = new RateLimiterMemory({
  keyPrefix: 'login_fail_consecutive_username_and_ip',
  points: maxWrongAttemptsByUsernameAndIP,
  duration: 60 * 60, // Store number for 1 hour since first fail
  blockDuration: 60 * 60, // Block for 1 hour
});

app.post('/', [
  body('username').trim().isLength({ min: 1 }).withMessage('Username cannot be empty.')
], async (req, res, next) => {
  // Remove rate limiter code for now
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const username = req.body.username;
  const ipAddr = req.ip;
  const usernameIPkey = `${username}_${ipAddr}`;

  try {
    await limiterSlowBruteByIP.consume(ipAddr);
    await limiterConsecutiveFailsByUsernameAndIP.consume(usernameIPkey);

    // Your authentication logic here
    // If authentication fails, throw an error

  } catch (err) {
    if (err instanceof Error) {
      // This block is reached when the promise is rejected by an actual error
      console.log(err);
      res.status(500).send("Error checking for existing user in the database.");
    } else {
      // This block is reached when the promise is rejected by rate-limiter
      res.status(429).send("Too Many Requests");
    }
  }
});

app.get('/:username', [
  param('username').trim().isLength({ min: 1 }).withMessage('Username cannot be empty.')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const username = req.params.username;
  connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).send('Error retrieving user data from the database.');
    }

    if (results.length > 0) {
      res.render('user', { title: 'User Profile', user: results[0] });
    } else {
      res.status(404).send('User not found');
    }
  });
});


app.listen(port, () => {
  console.log(`Express.js boilerplate app listening at http://localhost:${port}`);
});
