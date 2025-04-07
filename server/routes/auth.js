const express = require('express');
const { registerUser } = require('../controllers/auth');
const { validateUserInput, handleValidationErrors } = require('../js/auth');

const router = express.Router();

router.post(
    '/register',
    validateUserInput,
    handleValidationErrors,
    registerUser
);

module.exports = router;
