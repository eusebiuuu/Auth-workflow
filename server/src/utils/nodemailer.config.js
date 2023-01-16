const nodemailer = require('nodemailer');

const nodemailerConfig = () => {
  const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
      user: process.env.ETHEREAL_USER,
      pass: process.env.ETHEREAL_PASSWORD,
    }
  });
  return transporter;
}

module.exports = {
  nodemailerConfig,
}