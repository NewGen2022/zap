const express = require('express');
const userRouter = require('./routes/user');
const passwordRouter = require('./routes/password');
const tokenRouter = require('./routes/token');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const PORT = process.env.AUTH_SERVICE_PORT || 5000;

const server = express();

// Parse incoming JSON bodies (application/json)
server.use(express.json());

// Parse URL-encoded bodies (e.g. form submissions)
server.use(express.urlencoded({ extended: true }));

// Parse httpOnly cookies, needed for JWT refresh & access token cookies
server.use(cookieParser());

// Route for all auth-related operations (register, login, reset password, etc.)
server.use('/api/v1/auth', userRouter);
server.use('/api/v1/auth', passwordRouter);
server.use('/api/v1/auth', tokenRouter);

// Start listening for HTTP requests
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
