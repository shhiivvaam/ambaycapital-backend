const mongoose = require('mongoose');
const logger = require('./logger');
require('dotenv').config();

const clientOptions = {
    serverApi: {
        version: '1',
        strict: true,
        deprectionErrors: true,
    },
};

const db = async (req, res) => {
    try {
        // await mongoose.createConnection(process.env.MONGODB_URI, {
        //     // useNewUrlParser: true,
        //     // useUnifiedTopology: true,
        //     // serverSelectionTimeoutMS: 30000,
        //     maxPoolSize: 10,
        // });
        await mongoose.connect(process.env.MONGODB_URI, clientOptions);
        await mongoose.connection.db.admin().command({ ping: 1 });
        logger.info('Database connection established 🚀🚀');
    } catch (error) {
        logger.error(`Database connection Failed: ${error.message}`, error);
        res.status(500).send({ message: 'Failed to connect to MongoDB' });
        process.exit(1);
    }
}

module.exports = db;