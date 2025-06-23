const express = require('express');
const { sendResetPasswordLink } = require('../controllers/mail');

const router = express.Router();

router.post('/send-reset-link', sendResetPasswordLink);

module.exports = router;
