const express = require('express');
const router = express.Router();
const User = require('../model/user');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

// Apply Helmet globally for secure HTTP headers
router.use(helmet());

// Home route
router.get('/', (req, res) => {
  res.render('index', { title: 'User Management System' });
});

// Signup page
router.get('/signup', (req, res) => {
  res.render('signup');
});

// Handle signup form with input validation + password hashing
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Input validation
    if (!validator.isEmail(email)) {
      return res.status(400).send('Invalid email format');
    }
    if (!validator.isAlphanumeric(name)) {
      return res.status(400).send('Invalid name');
    }
    if (!validator.isLength(password, { min: 8 })) {
      return res.status(400).send('Password must be at least 8 characters');
    }

    // Password hashing
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.send(`Signup successful: ${name}`);
  } catch (err) {
    res.status(400).send('Error: ' + err.message);
  }
});

// Login page
router.get('/login', (req, res) => {
  res.render('login');
});

// Handle login with JWT authentication
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).send('Invalid credentials');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).send('Invalid credentials');

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });

    res.send({ message: 'Login successful', token });
  } catch (err) {
    res.status(500).send('Error: ' + err.message);
  }
});

// Protected profile route (requires token)
router.get('/profile', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).send('Access denied. No token provided.');

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, 'your-secret-key');
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).send('User not found');

    res.render('profile', { user });
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});

module.exports = router;
