const express = require('express');
const router = express.Router();
const User = require('../model/user');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const logger = require('../../utils/logger'); // import centralized logger

// Apply Helmet globally for secure HTTP headers
router.use(helmet());

// Home route
router.get('/', (req, res) => {
  logger.info('Home route accessed');
  res.render('index', { title: 'User Management System' });
});

// Signup page
router.get('/signup', (req, res) => {
  logger.info('Signup page accessed');
  res.render('signup');
});

// Handle signup form with input validation + password hashing
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Input validation
    if (!validator.isEmail(email)) {
      logger.warn(`Invalid signup email attempt: ${email}`);
      return res.status(400).send('Invalid email format');
    }
    if (!validator.isAlphanumeric(name)) {
      logger.warn(`Invalid signup name attempt: ${name}`);
      return res.status(400).send('Invalid name');
    }
    if (!validator.isLength(password, { min: 8 })) {
      logger.warn(`Weak password attempt for email: ${email}`);
      return res.status(400).send('Password must be at least 8 characters');
    }

    // Password hashing
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    logger.info(`New user registered: ${email}`);
    res.send(`Signup successful: ${name}`);
  } catch (err) {
    logger.error(`Signup error: ${err.message}`);
    res.status(400).send('Error: ' + err.message);
  }
});

// Login page
router.get('/login', (req, res) => {
  logger.info('Login page accessed');
  res.render('login');
});

// Handle login with JWT authentication
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    logger.info(`Login attempt for email: ${email}`);
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn(`Invalid login attempt for email: ${email}`);
      return res.status(401).send('Invalid credentials');
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      logger.warn(`Invalid password attempt for email: ${email}`);
      return res.status(401).send('Invalid credentials');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });

    logger.info(`Login successful for email: ${email}`);
    res.send({ message: 'Login successful', token });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).send('Error: ' + err.message);
  }
});

// Protected profile route (requires token)
router.get('/profile', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    logger.warn('Profile access denied: No token provided');
    return res.status(401).send('Access denied. No token provided.');
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, 'your-secret-key');
    const user = await User.findById(decoded.id);
    if (!user) {
      logger.warn(`Profile access failed: User not found for token ID ${decoded.id}`);
      return res.status(404).send('User not found');
    }

    logger.info(`Profile accessed for user: ${user.email}`);
    res.render('profile', { user });
  } catch (err) {
    logger.error(`Invalid token: ${err.message}`);
    res.status(401).send('Invalid token');
  }
});

module.exports = router;
