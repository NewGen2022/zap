const express = require('express');
const mailRouter = require('./routes/mail');
require('dotenv').config();

const PORT = process.env.MAIL_SERVICE_PORT || 5000;

const server = express();

// Parses incoming JSON requests (application/json)
server.use(express.json());

// Routes for email operations, under /api/v1/mail
server.use('/api/v1/mail', mailRouter);

// Starts HTTP server on configured port
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
