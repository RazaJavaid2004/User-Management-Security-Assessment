const express = require('express');
const router = express.Router();
const User = require('../model/user');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const logger = require('../../utils/logger'); 

// --- WEEK 4 NEW IMPORTS ---
const rateLimit = require('express-rate-limit');
const cors = require('cors');

// 1. Properly configure CORS to restrict unauthorized access 
router.use(cors({
  // UPDATED: Include both localhost and your network IP for testing
  origin: ['http://localhost:8080', 'http://192.168.56.50:8080'], 
  optionsSuccessStatus: 200
}));

// 2. Implement security headers with proper configuration

router.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], 
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));

// 3. Apply rate limiting to prevent brute-force attacks 
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, 
  message: 'Too many login attempts, please try again later.',
  handler: (req, res, next, options) => {
      // Logic: Logs the block so Fail2Ban can catch the "Brute-force attempt blocked" string
      logger.warn(`Brute-force attempt blocked for IP: ${req.ip}`);
      res.status(options.statusCode).send(options.message);
  }
});

// 4. Secure APIs using API keys

const apiKeyAuth = (req, res, next) => {
    const apiKey = req.header('x-api-key');
    if (!apiKey || apiKey !== 'super-secure-devhub-key') {
        // Logged for monitoring/auditing purposes
        logger.warn(`Unauthorized API access attempt from IP: ${req.ip}`);
        return res.status(401).send('Access denied. Invalid API key.');
    }
    next();
};

// --- ROUTES ---

router.get('/', (req, res) => {
  logger.info('Home route accessed');
  res.render('index', { title: 'User Management System' });
});

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    logger.info(`Login attempt for email: ${email}`);
    const user = await User.findOne({ email });
    
    // Check if user exists
    if (!user) {
      logger.warn(`Invalid login attempt for email: ${email} from IP: ${req.ip}`);
      return res.status(401).send('Invalid credentials');
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      logger.warn(`Invalid password attempt for email: ${email} from IP: ${req.ip}`);
      return res.status(401).send('Invalid credentials');
    }

    // Generate JWT
    const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });

    logger.info(`Login successful for email: ${email}`);
    res.send({ message: 'Login successful', token });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).send('Error: ' + err.message);
  }
});

// Secured API endpoint for Week 4 deliverables
router.get('/api/secure-data', apiKeyAuth, (req, res) => {
    logger.info('Secure API endpoint accessed successfully');
    res.json({ data: 'Confidential Developer Hub Corporation Data' });
});

module.exports = router;
