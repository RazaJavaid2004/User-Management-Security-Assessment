const express = require('express');
const router = express.Router();
const User = require('../model/user');
const logger = require('../../utils/logger'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// --- WEEK 4 SECURITY IMPORTS ---
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

// 1. CORS Configuration
router.use(cors({
    origin: ['http://localhost:8080', 'http://192.168.56.50:8080'],
    optionsSuccessStatus: 200
}));

// 2. Security Headers (Helmet) - Updated for Week 6 Compliance
router.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Removed 'unsafe-inline' for production hardening
      scriptSrc: ["'self'"], 
      objectSrc: ["'none'"],
      // Disable the forced HTTPS upgrade so local HTTP testing works
      upgradeInsecureRequests: null, 
    },
  },
  // Fix for Nikto finding: Explicitly enable MIME sniffing protection
  noSniff: true, 
  // Disable HSTS only for local dev environment
  hsts: false 
}));

// 3. Brute-Force Protection
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: 'Too many login attempts, please try again later.',
    handler: (req, res, next, options) => {
        logger.warn(`Brute-force attempt blocked for IP: ${req.ip}`);
        res.status(options.statusCode).send(options.message);
    }
});

// --- ROUTES ---

// Login Routes
router.get('/login', (req, res) => {
    res.render('login'); 
});

router.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send('Invalid credentials');
        }
        // NOTE: In production, move 'your-secret-key' to a .env file
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });
        // NOTE: Depending on how your frontend works, this might need to render the dashboard instead of sending JSON
        res.send({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
});

// --- WEEK 5/6: SIGNUP & REGISTRATION ---

router.get('/signup', (req, res) => {
    logger.info('Signup page accessed');
    res.render('signup'); 
});

router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        // FIX: Hash the password before saving to the database
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        
        logger.info(`New user registered: ${email}`);
        res.redirect('/login');
    } catch (err) {
        logger.error(`Signup error: ${err.message}`);
        res.status(500).send('Error creating user');
    }
});

router.get('/', (req, res) => {
    res.render('index', { title: 'User Management System' });
});

module.exports = router;
