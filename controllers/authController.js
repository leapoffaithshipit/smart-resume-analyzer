// backend/controllers/authController.js
const { ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');
const sendEmail = require('../utils/email');

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, req, res) => {
  const token = generateToken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + parseInt(process.env.JWT_EXPIRES_IN) * 24 * 60 * 60 * 1000 // e.g. 7 days
    ),
    httpOnly: true, // Cookie cannot be accessed or modified by the browser
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https', // HTTPS only
  };

  res.cookie('jwt', token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

exports.register = async (req, res, next) => {
  const db = req.app.locals.db; // Access db from app.locals
  try {
    const { name, email, password, passwordConfirm } = req.body;

    if (!name || !email || !password || !passwordConfirm) {
      return res.status(400).json({ status: 'fail', message: 'Please provide name, email, password, and password confirmation.' });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ status: 'fail', message: 'Please provide a valid email address.' });
    }

    if (password !== passwordConfirm) {
      return res.status(400).json({ status: 'fail', message: 'Passwords do not match.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ status: 'fail', message: 'Password must be at least 8 characters long.' });
    }

    const existingUser = await db.collection('users').findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ status: 'fail', message: 'Email already in use.' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationTokenExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const newUser = {
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      isVerified: false,
      emailVerificationToken,
      emailVerificationTokenExpires,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await db.collection('users').insertOne(newUser);
    const createdUser = { _id: result.insertedId, ...newUser }; // Construct user object with ID

    // Send verification email
    const verificationURL = `<span class="math-inline">\{process\.env\.CLIENT\_URL\}/verify\-email/</span>{emailVerificationToken}`;
    const message = `Hi <span class="math-inline">\{name\},\\n\\nPlease verify your email address by clicking the following link, or by pasting it into your browser's address bar\:\\n\\n</span>{verificationURL}\n\nIf you did not request this, please ignore this email.\nThis link will expire in 10 minutes.`;

    try {
      await sendEmail({
        email: createdUser.email,
        subject: 'Verify Your Email Address for Smart Resume Analyzer',
        message,
        html: `<p>Hi <span class="math-inline">\{name\},</<19\>p\><p\>Please verify your email address by clicking the link below\:</p\><p\><a href\="</span>{verificationURL}">Verify Email</a></p><p>If you did not create an account, please ignore this email.</p><p>This link will expire in 10 minutes.</p>`
      });
      res.status(201).json({
        status: 'success',
        message: 'Registration successful! Please check your email to verify your account.',
        // Optional: return user data or token if you want to auto-login,
        // but typically wait for verification.
      });
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
      // Potentially delete user or mark for re-verification if email fails critically
      return res.status(500).json({ status: 'error', message: 'User registered, but failed to send verification email. Please contact support or try registering again later.' });
    }

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during registration.' });
  }
};

exports.verifyEmail = async (req, res, next) => {
  const db = req.app.locals.db;
  try {
    const { token } = req.params;
    if (!token) {
      return res.status(400).json({ status: 'fail', message: 'Verification token is missing.' });
    }

    const user = await db.collection('users').findOne({
      emailVerificationToken: token,
      emailVerificationTokenExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ status: 'fail', message: 'Token is invalid or has expired. Please request a new one.' });
    }

    await db.collection('users').updateOne(
      { _id: user._id },
      {
        $set: {
          isVerified: true,
          updatedAt: new Date(),
        },
        $unset: { // Remove token fields after successful verification
          emailVerificationToken: "",
          emailVerificationTokenExpires: ""
        }
      }
    );

    // Log the user in by sending a token
    // Or just send a success message and let them log in manually
    createSendToken(user, 200, req, res);
    // res.status(200).json({ status: 'success', message: 'Email verified successfully! You can now log in.' });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during email verification.' });
  }
};


exports.login = async (req, res, next) => {
  const db = req.app.locals.db;
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password.' });
    }

    const user = await db.collection('users').findOne({ email: email.toLowerCase() });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password.' });
    }

    if (!user.isVerified) {
      // Optional: Resend verification email
      // For now, just inform them
      return res.status(401).json({ status: 'fail', message: 'Your email is not verified. Please check your inbox for the verification link or request a new one.' });
    }

    createSendToken(user, 200, req, res);

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during login.' });
  }
};

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000), // Expires in 10 seconds
    httpOnly: true,
  });
  res.status(200).json({ status: 'success', message: 'Logged out successfully.' });
};