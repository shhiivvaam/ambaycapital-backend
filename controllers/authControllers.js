const User = require('../models/Users');
const jwt = require('jsonwebtoken');
const crypto = require("crypto");
// const bcrypt = require('bcrypt');
require("dotenv").config();
const logger = require('../config/logger');
const EmailConfig = require('../config/emailConfig');

const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (payload, ttl = "1h") => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: ttl });
};

const generateCSRFToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

const revokedTokens = new Set();   // TODO: Need to add this to the db instead of im-memory storage

const isTokenRevoked = (token) => {
    return revokedTokens.has(token);
};

const revokeToken = (token) => {
    revokedTokens.add(token);
};

const refreshToken = async (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        logger.warn("Refresh token missing in request");
        return res.status(401).json({ message: "Refresh token is missing" });
    }

    if (isTokenRevoked(refreshToken)) {
        logger.warn("Attempt to use revoked refresh token");
        return res.status(403).json({ message: "Token has been revoked" });
    }

    try {
        const decode = jwt.verify(refreshToken, JWT_SECRET);

        const new_token = generateToken({ id: decode.id, role: decode.role }, "1h");

        res.cookie(
            "token",
            new_token,
            {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
                maxAge: 60 * 60 * 1000,  // 60 minutes
            }
        );

        logger.info(`Token refreshed successfully for user ${decode.id}`);
        return res.status(200).json({ message: "Token refreshed successfully", refreshToken: new_token });
    } catch (error) {
        logger.error(`Token verification failed: ${error.message}`);
        // revokeToken(refreshToken);   // TODO: check this

        // Handle token verification errors
        if (error.name === "TokenExpiredError") {
            return res.status(403).json({ message: "Refresh token has expired" });
        }
        return res.status(401).json({ message: "Invalid refresh token" });
    }
}

const logout = (req, res) => {
    const { refreshToken } = req.cookies;

    if (refreshToken) {
        revokeToken(refreshToken);
        logger.info(`Refresh token revoked during logout for user ${req?.user?.id}`);
    }
    res.clearCookie("token");
    res.clearCookie("refreshToken");
    res.clearCookie("csrfToken");

    logger.info(`Logout successful for user ${req?.user?.id}`);

    res.status(200).json({ message: "Logout successful" });
}

const login = async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        logger.error('username or password not provided');
        return res.status(400).json({ message: 'username and password are required' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user || !(await user.comparePassword(password))) {
            logger.warn("Invalid credentials attempt for", username, password);
            // return res.status(401).json({ message: 'Invalid Credentails' });
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const token = generateToken({ id: user._id, role: user.role });
        const refreshToken = generateToken({ id: user._id, role: user.role }, "7d");
        const csrfToken = generateCSRFToken();

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",  // only on HTTPS in PRODUCTION,
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax", // only on HTTP in DEVELOPMENT  && prevent CSRF
            maxAge: 60 * 60 * 1000, // 1 hour
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,  // 7d
        });

        res.cookie("csrfToken", csrfToken, {
            httpOnly: false, // should be accessible by client-side scripts
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
            maxAge: 1 * 60 * 60 * 1000,  // 1h
        });

        logger.info(`User ${user._id} logged in successfully`);

        const userDetails = {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role
        }
        res.status(200).json({
            message: "Login successful",
            userDetails,
            token
        });
    } catch (error) {
        logger.error(`Error during login for user ${username}: ${error.message}`);
        res.status(500).json({ message: "Internal server error" });
    }
}

const registerOwner = async (req, res) => {
    const { username, password, email, authCode } = req.body;

    try {
        if(!authCode || authCode !== process.env.AUTH_CODE) {
            logger.error("Authorization Code is Incorrect");
            return res.status(400).json({ message: "Authorization Code is Incorrect" });
        }
        if (!username || !password || !email) {
            return res.status(400).json({ message: "All fields (username, password, email) are required." });
        }

        const usernameRegex = /^[a-z0-9]+$/; // Lowercase and no spaces/special characters
        if (!usernameRegex.test(username)) {
            logger.error("Username does not meet requirements");
            return res.status(400).json({
                message: "Username must be lowercase and contain no spaces or special characters."
            });
        }

        // 8 chars, 1 uppercase, 1 digit
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(password)) {
            logger.error("Password does not meet requirements");
            return res.status(400).json({
                message: "Password must be at least 8 characters long, contain at least one digit and one uppercase letter."
            });
        }

        const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
        if (!emailRegex.test(email)) {
            logger.error("Invalid email format");
            return res.status(400).json({
                message: "Please provide a valid email address."
            });
        }

        const user = await User.findOne({ $or: [{ username }, { email }] });
        if (user) {
            logger.error(`Username: ${username} or Email ${email} already exists`);
            return res.status(400).json({ message: "Username or Email already exists" });
        }

        const newUser = new User({
            username,
            password,
            email,
            role: "owner"
        });
        const savedUser = await newUser.save();

        // Send account confirmating email
        const subject = "AmbayCapital - Account Created Successfully";
        const html = `
                <p>Your account has been created successfully.</p>
                <a href="${process.env.WEB_URL}/login">Login Here</a>
            `;

        const mailStatus = await EmailConfig.sendMail(email, subject, html);

        if (!mailStatus.success) {
            logger.error(`Failed to send Account Confirmating Email to ${email}: ${mailStatus.message}`);
            return res.status(500).json({ message: "Failed to send Account Confirmating Email", error: mailStatus.message });
        }

        logger.info(`Account Confirmation Email successfully sent to ${email}`);

        return res.status(201).json({
            message: "Owner Added Successfully",
            data: {
                id: savedUser.id,
                username: savedUser.username,
                email: savedUser.email,
                role: savedUser.role
            }
        });
    }
    catch (error) {
        logger.error(`Error registering owner for ${username}: ${error.message}`);
        return res.status(500).json({ message: "Internal server error", error: error.message });
    }
}

const sendManagerInvite = async (req, res) => {

    let email;

    try {
        ({ email } = req.body);

        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists for this email" });
        }

        // sending a invite with token for validation
        const token = generateToken({ email }, "1h");

        const url = `${process.env.WEB_URL}/verify-manager?token=${token}`;
        const subject = "AmbayCapital - Manager Account Invitation";
        const html = `
        <p>You have been invited to configure your manager account. <br/> Verify yourself by clicking the link:</p>
        <a href="${url}">Verify Account</a>
    `;

        const mailStatus = await EmailConfig.sendMail(email, subject, html);
        if (!mailStatus.success) {
            logger.error(`Error sending email invite to ${email}: ${error.message}`);
            return res.status(500).json({ message: "Error Sending Email Invite", error: error.message });
        }

        logger.info(`Email invite sent to ${email}`);
        return res.status(200).json({ message: "Email Invite sent successfully" });
    } catch (error) {
        logger.error(`Error sending email invite to ${email}: ${error.message}`);
        return res.status(500).json({ message: "Error Sending Email Invite", error: error.message });
    }
}

const registerManager = async (req, res) => {
    const { token, username, password } = req.body;

    if (!token) {
        logger.error("Authorization Token is missing for: ", username);
        return res.status(400).json({ message: "Authorization Token is missing" });
    }

    if (!username || !password) {
        logger.error("Username and password are required for: ", username);
        return res.status(400).json({ message: "Username and password are required." });
    }

    const usernameRegex = /^[a-z0-9]+$/; // Lowercase and no spaces/special characters
    if (!usernameRegex.test(username)) {
        return res.status(400).json({
            message: "Username must be lowercase and contain no spaces or special characters."
        });
    }

    // 8 chars, 1 uppercase, 1 digit
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            message: "Password must be at least 8 characters long, contain at least one digit and one uppercase letter."
        });
    }

    try {
        const decode = jwt.verify(token, JWT_SECRET);
        const email = decode.email;
        // const { email } = jwt.verify(token, JWT_SECRET);

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            logger.error(`Username ${username} already exists`);
            return res.status(400).json({ message: "Username already exists." });
        }

        // const hashedPassword = await bcrypt.hash(password, 10);  // we are already hashing the password in the model before saving
        const newUser = new User({ username, email, password, role: "manager" });
        await newUser.save();

        logger.info(`Manager Account created successfully for ${username}`);

        const subject = "AmbayCapital - Account Created Successfully";
        const html = `
                <p>Your account has been created successfully.</p>
                <a href="${process.env.WEB_URL}/login">Login Here</a>
            `;

        const mailStatus = await EmailConfig.sendMail(email, subject, html);
        if (!mailStatus.success) {
            logger.error(`Failed to send Account Confirmating Email to ${email}: ${mailStatus.message}`);
            return res.status(500).json({ message: "Failed to send Account Confirmating Email", error: mailStatus.message });
        }
        logger.info(`Account Confirmating Email successfully sent to ${email}`);
        return res.status(200).json({ message: "Account Confirmating Email sent successfully" });
    } catch (error) {
        logger.error(`Error saving manager credentials for ${username}: ${error.message}`);
        res.status(500).json({ message: "Internal server error" });
    }
}

module.exports = {
    refreshToken,
    logout,
    login,
    registerOwner,
    sendManagerInvite,
    registerManager,
};