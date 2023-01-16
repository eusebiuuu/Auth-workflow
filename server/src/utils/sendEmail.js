
const sendEmail = async (transporter, destination, subject, htmlBody) => {
  return await transporter.sendMail({
    from: 'Rimboi Eusebiu <eusebiuu@gmail.com>', // shown sender adress
    to: destination,
    subject: subject,
    html: htmlBody,
  });
}

module.exports = {
  sendEmail,
}