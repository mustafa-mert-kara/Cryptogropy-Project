const jsonwebtoken = require("jsonwebtoken");

const generateJWToken = (id) => {
  console.log("In Token Creation", "AnyKey")
  return jsonwebtoken.sign({ id }, "AnyKey", {
    expiresIn: "10d",
  });
};

module.exports = generateJWToken;
