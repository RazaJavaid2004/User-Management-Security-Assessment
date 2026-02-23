const express = require('express');
const router = express.Router();
const User = require('../model/user');

// Home route
router.get('/', (req, res) => {
  res.render('index', { title: 'User Management System' });
});

// Signup page
router.get('/signup', (req, res) => {
  res.render('signup');
});

// Handle signup form
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const user = new User({ name, email, password });
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

router.post('/login', async (req, res) => {
  try {
    // Directly trust whatever comes in the body
    const user = await User.findOne(req.body);
    if (user) {
      res.render('profile', { user });
    } else {
      res.status(401).send('Invalid credentials');
    }
  } catch (err) {
    res.status(500).send('Error: ' + err.message);
  }
});

// Profile page
router.get('/profile', (req, res) => {
  res.render('profile', { user: { name: 'Test User', email: 'test@example.com' } });
});

module.exports = router;
