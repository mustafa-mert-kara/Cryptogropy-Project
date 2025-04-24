const asyncHandler = require("express-async-handler");
const { CustomError } = require("../error/custom");
const MessageModel = require("../models/Message");
const UserModel = require("../models/User");
const ChatModel = require("../models/Chat");
const { spawnSync } = require('child_process');
// const chats = require("../data/data");

const editMessage = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  if (!content) {
    throw new CustomError("Invalid data", 400);
  }
  try {
    const data = await MessageModel.findByIdAndUpdate(
      id,
      {
        content: content,
      },
      { new: true }
    )
      .populate("sender", "username image")
      .populate("chat");
    res.status(200).json(data);
  } catch (err) {
    throw new CustomError("Unable to edit message", 400);
  }
});

const deleteMessage=asyncHandler(async(req,res)=>{
  const { id } = req.params;

  try {
    const data = await MessageModel.findByIdAndUpdate(
      id,
      {
        isDeleted: true,
      },
      { new: true }
    )
      .populate("sender", "username image")
      .populate("chat");
    res.status(200).json(data);
  } catch (err) {
    throw new CustomError("Unable to delete message", 400);
  }
})

function runCryptoScript(message,type,key=null,RC_type="rc6"){
  let args=[]
  if(RC_type=="rc5"){
    args.push('Encryption/RC5.py') 
  }    
  else{
    args.push('Encryption/RC6.py') 
  }
  args.push(type)
  args.push(message)
  if(key){
    args.push(key)
  }
  console.log(args)
  const childProcess = spawnSync('python', args);
  // childProcess.stdout.setEncoding('utf-8');
  let data=childProcess.stdout.toString('utf8') 
if (type=="encrypt"){
  let [key,cipher] =data.split(" ");
 
  return [key,cipher]
}else{
  return data;
}
}

const messageSender = asyncHandler(async (req, res) => {
  const { content, chatId,encryptionType } = req.body;

  if (!content || !chatId) {
    //   console.log("Invalid data");
    throw new CustomError("Invalid data", 400);
  }
  const  [key,cipher]=runCryptoScript(content,"encrypt",RC_type=encryptionType);
  console.log("Returned Key",key,"cipherText:",cipher,"EncryptionType:",encryptionType);
  var newMessage = {
    sender: req.user._id,
    content: cipher,
    chat: chatId,
    key:key,
    encryptionType:encryptionType,
    isDeleted: false,
  };
  try {
    var message = await MessageModel.create(newMessage);
    message = await message.populate("sender", "username image");
    message = await message.populate("chat");
    message = await UserModel.populate(message, {
      path: "chat.users",
      select: "username image gmail",
    });

    
    await ChatModel.findByIdAndUpdate(req.body.chatId, {
      latestMessage: message,
    });
    res.status(200).json(message);
  } catch (error) {
    throw new CustomError("Unable to store message", 400);
  }
});

const getAllMessages = asyncHandler(async (req, res) => {
  console.log("Inside getAllMessages")
  try {
    const { id } = req.params;
    let data = await MessageModel.find({ chat: id });
    if (data.length === 0) {
      console.log("Inside Data length")
      res.status(200).json(data);
      return;
    }
    
    data = await MessageModel.find({ chat: id })
      .populate("sender", "username image")
      .populate("chat");
    for(const val of data) {
      const content=runCryptoScript(val.content,"decrypt",val.key,RC_type=val.encryptionType)
      console.log(content)
      val.content=content
  }
    res.status(200).json(data);
  } catch (err) {
    console.log(err);
    throw new CustomError("Unable to fetch messages", 400);
  }
});

module.exports = {
  messageSender,
  getAllMessages,
  editMessage,
  deleteMessage,
  runCryptoScript
};
