const express = require('express');
const authRouter = require('./routes/auth');
require('dotenv').config();

const PORT = process.env.PORT || 5000;

app = express();

app.use(express.json()); // for parsing JSON bodies
app.use(express.urlencoded({ extended: true })); // for parsing form data

app.use('/api', authRouter);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
