const nodeMailer = require('nodemailer');
require('dotenv').config();

const transporter = nodeMailer.createTransport({
    service: process.env.SMTP_SERVICE,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

const sendEmailMsg = async (email, subject, text, html) => {
    await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject,
        text,
        html,
    });
};

module.exports = { sendEmailMsg };
