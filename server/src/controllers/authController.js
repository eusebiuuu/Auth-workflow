const User = require('../models/User');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const { attachCookiesToResponse, createTokenUser, sendVerificationEmail, sendResetPasswordEmail, hashToken } = require('../utils');
const crypto = require('crypto');
const Token = require('../models/Token');

const register = async (req, res) => {
  const { email, name, password } = req.body;
  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';
  const verificationToken = crypto.randomBytes(30).toString('hex');
  const user = await User.create({ name, email, password, role, verificationToken });
  const origin = 'http://localhost:3000';
  await sendVerificationEmail(name, email, verificationToken, origin);
  res.status(StatusCodes.CREATED).json({
    msg: 'Please check your email',
    verificationToken: user.verificationToken,
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });
  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid password');
  }
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError('Validate your email');
  }
  let refreshToken = '';
  const tokenUser = createTokenUser(user);
  const existingToken = await Token.findOne({ user: user._id });
  if (existingToken) {
    if (!existingToken.isValid) {
      throw new CustomError.UnauthenticatedError('Invalid credentials');
    }
    refreshToken = existingToken.refreshToken;
  } else {
    refreshToken = crypto.randomBytes(30).toString('hex');
    const userAgent = req.headers['user-agent'];
    const ip = req.ip;
    const token = await Token.create({ refreshToken, userAgent, ip, user: user._id });
    console.log(token);
  }
  attachCookiesToResponse({ res, user: tokenUser, refreshToken });
  res.status(StatusCodes.OK).json({ user: tokenUser, refreshToken });
};

const logout = async (req, res) => {
  await Token.deleteOne({
    user: req.user.userId,
  });
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  console.log(verificationToken, email);
  if (!email) {
    throw new CustomError.BadRequestError('Invalid email provided');
  }
  const user = await User.findOne({ email });
  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid credentials1');
  }
  // console.log(user);
  if (verificationToken !== user.verificationToken) {
    throw new CustomError.UnauthenticatedError('Invalid credentials2');
  }
  user.isVerified = true;
  user.verified = new Date(Date.now());
  user.verificationToken = '';
  await user.save();
  const userToken = createTokenUser(user);
  attachCookiesToResponse({ res, user: userToken });
  res.status(StatusCodes.OK).json({ msg: 'Email verified!' });
}

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError.UnauthenticatedError('Email must be provided');
  }
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(StatusCodes.OK).json({
      msg: 'Check your email',
    });
  }
  const passwordToken = crypto.randomBytes(40).toString('hex');
  const expirationPeriod = 1000 * 60 * 10;
  const passwordTokenExpirationDate = new Date(Date.now() + expirationPeriod);
  user.passwordToken = hashToken(passwordToken);
  user.passwordTokenExpirationDate = passwordTokenExpirationDate;
  await user.save();
  const origin = 'http://localhost:3000';
  await sendResetPasswordEmail({
    name: user.name,
    email: user.email,
    token: passwordToken,
    origin,
  });
  res.status(StatusCodes.OK).json({
    msg: 'Check your email',
  });
}

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!password) {
    throw new CustomError.BadRequestError('Please provide the password');
  }
  const user = await User.findOne({
    passwordToken: hashToken(token),
    email,
  });
  if (!user) {
    return res.status(StatusCodes.OK).json({
      msg: 'Password changed successfully!',
    });
  }
  const currentDate = Date.now();
  if (user.passwordTokenExpirationDate < currentDate) {
    throw new CustomError.UnauthorizedError('The period to reset your password ended. Please do the process again');
  }
  user.password = password;
  user.passwordToken = user.passwordTokenExpirationDate = null;
  await user.save();
  return res.status(StatusCodes.OK).json({
    msg: 'Password changed successfully!',
  });
}

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
