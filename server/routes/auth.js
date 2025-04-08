const express = require('express');
const {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
} = require('../controllers/auth');
const {
    validateUserInput,
    handleValidationErrors,
    validateLoginInput,
    checkRateLimit,
} = require('../middleware/auth');

const router = express.Router();

router.post(
    '/register',
    validateUserInput,
    handleValidationErrors,
    registerUser
);

router.post(
    '/login',
    validateLoginInput,
    handleValidationErrors,
    checkRateLimit,
    loginUser
);

router.post('/logout', logoutUser);

router.post('/refresh', refreshAccessToken);

module.exports = router;
