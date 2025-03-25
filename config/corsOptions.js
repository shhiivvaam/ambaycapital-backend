require('dotenv').config();
const logger = require('./logger');

const allOrigins = [
    process.env.WEB_LOCAL_URL,
    process.env.WEB_DEV_URL,
    process.env.WEB_PROD_URL,
].filter(Boolean); // filtering our undefined values

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : allOrigins

const corsOptions = {
    origin: (origin, callback) => {

        if (!allowedOrigins.length || !allowedOrigins) {
            logger.warn('No allowed origins defined. CORS will deny all requests.');
        }

        if (!origin) {
            // POSTMAN - non browser requests
            logger.warn('Access granted for non-browser request (no origin)');
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            logger.info(`Access granted from ${origin}`);
            return callback(null, true);
        }

        logger.error(`Access denied for ${origin}`);
        callback(new Error('CORS policy does not allow access from this origin'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
    credentials: true,                        // (cookies, etc.)
    optionsSuccessStatus: 200,                // status for preflight requests
};

module.exports = corsOptions;