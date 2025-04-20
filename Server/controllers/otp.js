const asyncHandler = require("express-async-handler");
const { CustomError } = require("../error/custom");
const UserModel = require("../models/User");
const TokenModel = require("../models/Token");
const generateJWToken = require("../config/webtoken");
const sendEmail = require("../utils/sendEmail");

const sendOTP = asyncHandler(async (req, res) => {
  try {
    
    res.status(200).send("Verification link sent successfully!");
  } catch (err) {
    console.log(err);
    throw new CustomError("Can't send the message", 400);
  }
});

const verifyOTP = asyncHandler(async (req, res) => {
  try {
    
    res
      .status(200)
      .send(
        "Email verified successfully! You can now close this tab and login into the chat app"
      );
  } catch (error) {
    console.log(error);
    throw new CustomError("Invalid link", 400);
  }
});

module.exports = {
  sendOTP,
  verifyOTP,
};
