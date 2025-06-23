const express = require('express');
const authRouter = require('./routes/auth');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const PORT = process.env.AUTH_SERVICE_PORT || 5000;

const server = express();

server.use(express.json()); // for parsing JSON bodies
server.use(express.urlencoded({ extended: true })); // for parsing form data
server.use(cookieParser()); // for parsing cookies

server.use('/api/v1/auth', authRouter);

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
