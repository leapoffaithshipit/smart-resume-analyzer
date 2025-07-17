// backend/utils/email.js
const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  // 1) Create a transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    // For services like Gmail, you might need to enable "less secure app access"
    // or use an app-specific password. For production, consider services like SendGrid, Mailgun.
    ...(process.env.EMAIL_HOST === 'smtp.gmail.com' && { tls: { rejectUnauthorized: false } }) // Add this for Gmail if you face SSL issues locally
  });

  // 2) Define the email options
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: options.email,
    subject: options.subject,
    text: options.message,
    html: options.html, // You can send HTML emails too
  };

  // 3) Actually send the email
  try {
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('There was an error sending the email. Try again later!');
  }
};

module.exports = sendEmail;