const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const verifyToken = (req, res, next) => {

    let token = req.cookies.token || req.headers.token;

    if (!token && (req.headers.authorization || req.headers.Authorization)) {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (authHeader.startsWith("Bearer ")) {
            token = authHeader.split(" ")[1];
        }
    }

    if (!token) {
        return res.status(401).json("You are not authenticated!");
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json("Invalid Aithorization Token!");
        }
        req.user = user;  // attaching the decoded user info to the request
        next();
    });

};

const verifyRole = (requiredRole) => (req, res, next) => {
    const {role} = req.user;

    if(role !== requiredRole) {
        return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
};

const verifyAccess = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.role === "owner" || req.user.role === "manager") {
            // if (req.user.id === req.params.id || req.role === "owner") {
            next();
        } else {
            res.status(403).json("You are not allowed to do that!");
        }
    });
}

const verifyAccessOwner = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.role === "manager") {
            next();
        } else {
            res.status(403).json("You are not allowed to do that!");
        }
    });
}

const csrfProtection = (req, res, next) => {
    const csrfToken = req.headers["x-csrf-token"];
    if (!csrfToken || csrfToken !== req.cookies.csrfToken) {
        logger.warn("CSRF validation failed");
        return res.status(403).json({ message: "CSRF validation failed" });
    }
    next();
};

module.exports = {
    verifyToken,
    verifyRole,
    verifyAccess,
    verifyAccessOwner,
    csrfProtection,
};