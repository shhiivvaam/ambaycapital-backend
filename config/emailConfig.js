const nodemailer = require("nodemailer");
const logger = require("./logger");

const transporter = nodemailer.createTransport({
    service: "Gmail",
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // true for 465, false for other ports
    auth: {
        user: process.env.NODEMAILER_EMAIL,
        pass: process.env.NODEMAILER_PASSKEY,
    },
});

const sendMail = async (to, subject, html) => {
    const mailOptions = {
        from: process.env.NODEMAILER_EMAIL,
        to,
        subject,
        html,
    }

    try {
        if (!process.env.NODEMAILER_EMAIL ||!process.env.NODEMAILER_PASSKEY) {
            logger.error("Missing email credentials");
            return {success: false, message: "Missing email credentials"};
            // throw new Error("Missing email credentials");
        }

        const info = await transporter.sendMail(mailOptions);
        logger.info(`Email sent to ${to}: ${info.response}`);
        return {success: true, info};
    } catch (error) {
        logger.error(`Error sending email to ${to}: ${error.message}`);
        return {success: false, message: error.message};
    }
}

module.exports = {
    transporter,
    sendMail,
};