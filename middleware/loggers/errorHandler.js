const logger = require("../../config/logger");

const errorHandler = (err, req, res, next) => {

    if(err.name === 'Error' && err.message === "Not allowed by CORS") {
        logger.warn(`CORS Blocked: ${req.method} ${req.originalUrl} from ${req.get('origin')}`);
        return res.status(403).json({ message: 'CORS policy does not allow access from this origin' });
    }

    logger.error(`Error: ${er.message} | Stack: ${err.stack}`);
    res.status(err.status || 500).json({
        message: err.message || "Internal Server Error",
    });
}

module.exports = errorHandler;