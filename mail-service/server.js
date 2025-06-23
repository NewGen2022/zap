const express = require('express');
const mailRouter = require('./routes/mail');
require('dotenv').config();

const PORT = process.env.MAIL_SERVICE_PORT || 5000;

const server = express();

server.use(express.json());

server.use('/api/v1/mail', mailRouter);

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
