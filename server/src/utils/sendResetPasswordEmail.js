const { nodemailerConfig } = require("./nodemailer.config");
const { sendEmail } = require("./sendEmail");

const sendResetPasswordEmail = async ({ name, email, origin, token }) => {
  const transporter = nodemailerConfig();
  const uri = `${origin}/user/reset-password?token=${token}&email=${email}`;
  const link = `<a href=${uri}>this page</a>`;
  const htmlMessage = `<p>Please go to ${link} to reset your password.</p>`;
  await sendEmail(transporter, email, 'Password reset', `<h4>Hello ${name}!<h4> ${htmlMessage}`);
}

module.exports = {
  sendResetPasswordEmail,
}