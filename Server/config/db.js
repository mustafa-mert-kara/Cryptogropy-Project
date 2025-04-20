const { connect } = require("mongoose");

const options = {
  useUnifiedTopology: true,
  useNewUrlParser: true,
};

const username = encodeURIComponent("mustafamkara97");

const password = encodeURIComponent("MustafaPassword1");


let uri =
  `mongodb+srv://${username}:${password}@cluster0.ubrqxpo.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const connectDB = () => {
  return connect(uri, options);
};

module.exports = connectDB;
