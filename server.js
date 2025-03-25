const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const db = require("./config/db");
const logger = require("./config/logger");
const errorHandler = require("./middleware/loggers/errorHandler"); 
const requestLogger = require("./middleware/loggers/requestLogger");
const corsOptions = require("./config/corsOptions");
const router = require("./routes/routes");

require("dotenv").config();
db();

const PORT = process.env.PORT;

const app = express();
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use(requestLogger);
app.use(errorHandler);

app.use('/', router);

app.listen(PORT, () => {
    logger.info("Server listening!👍👍")
});

// TODO: check below
// app.listen = function (PORT, callback) {
//     return new Promise((resolve, reject) => {
//         const server = this.server = app.listen(PORT, () => {
//             if (callback) callback();
//             // callback && callback();
//             logger.info("Server listening!👍👍");
//             resolve(server);
//         });
//         // server.on('error', reject);
//         server.on('error', (err) => {
//             logger.error("Server not listening!👎👎", err);
//             reject(err);
//         });
//     });
// }

module.exports = app;
