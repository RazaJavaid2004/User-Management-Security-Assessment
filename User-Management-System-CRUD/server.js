const express = require('express');
const dotenv = require('dotenv');
const morgan = require('morgan');
const bodyparser = require('body-parser');
const path = require('path');
const connectDB = require('./server/database/connection');
const app = express();

dotenv.config({ path: 'config.env' });
const PORT = process.env.PORT || 8080;

// log request
app.use(morgan('tiny'));

// mongoDB connection
connectDB();

// parse request to bodyparser
app.use(bodyparser.urlencoded({ extended: true }));
app.use(express.json()); // ⚠️ allow raw JSON bodies

// set view engine
app.set('view engine', 'ejs');

// load assets
app.use('/CSS', express.static(path.resolve(__dirname, 'assets/CSS')));
app.use('/img', express.static(path.resolve(__dirname, 'assets/img')));
app.use('/js', express.static(path.resolve(__dirname, 'assets/js')));

// load router
app.use('/', require('./server/route/router'));

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT} ...`));
