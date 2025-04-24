const mongoose = require("mongoose");

const MessageSchema = new mongoose.Schema(
  {
    content: {
      type: String,
      trim: true,
    },
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    chat: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Chat",
    },
    key: {
      type: String,
      default: false,
    },
    encryptionType: {
      type: String,
      default: false,
    },
    isDeleted: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

const Messages =
  mongoose.models.Messages || mongoose.model("Message", MessageSchema);

module.exports = Messages;
