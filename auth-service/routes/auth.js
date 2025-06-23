const express = require('express');
const {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    forgotPassword,
    resetPassword,
} = require('../controllers/auth');
const {
    validateUserInput,
    handleValidationErrors,
    validateLoginInput,
} = require('../middleware/auth');
const { checkRateLimit } = require('../middleware/rateLimit');

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

router.post('/forgot-password', forgotPassword);

router.post('/reset-password', resetPassword);

module.exports = router;
