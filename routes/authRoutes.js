const express = require('express');
const jwt = require('jsonwebtoken');

// controllers
const authControllers = require('../controllers/authControllers');

const router = express.Router();

router.post('/login', authControllers.login);
router.post('/refresh-token', authControllers.refreshToken);
router.post('/register-owner', authControllers.registerOwner);
router.post('/invite-manager', authControllers.sendManagerInvite);
router.post('/register-manager', authControllers.registerManager);
router.post('/logout', authControllers.logout);

module.exports = router;