require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const requestId = require('./middleware/requestId');
const logger = require('./utils/logger');

const userRouter = require('./routes/user');
const passwordRouter = require('./routes/password');
const tokenRouter = require('./routes/token');

const PORT = process.env.AUTH_SERVICE_PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'dev';

const server = express();
logger.info('Auth service booting...', {
    action: 'boot',
    env: NODE_ENV,
    port: PORT,
});

// Parse incoming JSON bodies (application/json)
server.use(express.json());

// Parse URL-encoded bodies (e.g. form submissions)
server.use(express.urlencoded({ extended: true }));

// Parse httpOnly cookies, needed for JWT refresh & access token cookies
server.use(cookieParser());

// Adds id for every request
server.use(requestId);

// Route for all auth-related operations (register, login, reset password, etc.)
server.use('/api/v1/auth', userRouter);
server.use('/api/v1/auth', passwordRouter);
server.use('/api/v1/auth', tokenRouter);

// Start listening for HTTP requests
server.listen(PORT, () => {
    logger.info('Auth service listening', { action: 'listen', port: PORT });
});
