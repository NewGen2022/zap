require('dotenv').config();
const express = require('express');
const mailRouter = require('./routes/mail');
const logger = require('./utils/logger');

const PORT = process.env.MAIL_SERVICE_PORT || 5000;

const server = express();

// Parses incoming JSON requests (application/json)
server.use(express.json());

// Routes for email operations, under /api/v1/mail
server.use('/api/v1/mail', mailRouter);

// Starts HTTP server on configured port
server.listen(PORT, () => {
    logger.info('Auth service listening', {
        action: 'listen',
        port: PORT,
    });
});
