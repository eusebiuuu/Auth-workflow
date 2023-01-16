const { isTokenValid, attachCookiesToResponse } = require('./jwt');
const createTokenUser = require('./createTokenUser');
const checkPermissions = require('./checkPermissions');
const { sendEmail } = require('./sendEmail');
const { sendResetPasswordEmail } = require('./sendResetPasswordEmail');
const { sendVerificationEmail } = require('./sendVerificationEmail');
const { hashToken } = require('./createHash');

module.exports = {
  isTokenValid,
  attachCookiesToResponse,
  createTokenUser,
  checkPermissions,
  sendEmail,
  sendResetPasswordEmail,
  sendVerificationEmail,
  hashToken,
};
