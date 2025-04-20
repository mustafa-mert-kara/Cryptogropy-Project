const jwt = require("jsonwebtoken");
const UserModel = require("../../models/User");
const asyncHandler = require("express-async-handler");
const { CustomError } = require("../../error/custom");

const authorizer = asyncHandler(async (req, res, next) => {
  console.log("burdayim")
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      console.log("burdayim")
      token = req.headers.authorization.split(" ")[1];
      console.log("token",token,"Key","AnyKey")
      //decodes token id
      const decoded = jwt.verify(token, "AnyKey");
      console.log("decoded",decoded)
      req.user = await UserModel.findById(decoded.id).select("-password");

      next();
    } catch (error) {
      throw new CustomError("Authorization failed!", 401);
    }
  }

  if (!token) {
    throw new CustomError("No token specified to authorize!", 401);
  }
});

module.exports = { authorizer };
