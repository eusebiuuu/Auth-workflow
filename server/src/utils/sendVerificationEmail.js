const { nodemailerConfig } = require("./nodemailer.config");
const { sendEmail } = require("./sendEmail");

const sendVerificationEmail = async (name, email, verificationToken, origin) => {
  const transporter = nodemailerConfig();
  // take origin from req object: https://www.udemy.com/course/nodejs-tutorial-and-projects-course/learn/lecture/29002556#overview
  const uri = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;
  const link = `<a href=${uri}> confirm here</a>`;
  const htmlMessage = `<p>Please confirm your email adress by clicking on this link: ${link}</p>`;
  await sendEmail(transporter, email, 'Email confirmation', `<h4>Hello ${name}!<h4> ${htmlMessage}`);
}

module.exports = {
  sendVerificationEmail,
}