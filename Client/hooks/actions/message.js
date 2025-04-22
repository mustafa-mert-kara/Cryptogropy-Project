import actiontypes from "../action-types/actiontypes";

export const ADD_MESSAGE = (message, id) => {
  console.log("Inside ADD_Message")
  return {
    type: actiontypes.ADD_FRIEND,
    message: message,
    id: id,
  };
};

export const DELETE_MESSAGE = (id, index) => {
  return {
    type: actiontypes.DELETE_MESSAGE,
    id: id,
    index: index,
  };
};
export const EDIT_MESSAGE = (message, chatId, index) => {
  return {
    type: actiontypes.EDIT_MESSAGE,
    message: message,
    id: chatId,
    index: index,
  };
};

export const ADD_USER_MESSAGE = (id, messages) => {
  console.log("Inside ADD_USER_Message")
  return {
    type: actiontypes.ADD_USER_MESSAGE,
    messages: messages,
    id: id,
  };
};

export const REMOVE_USER_MESSAGE = (id) => {
  return {
    type: actiontypes.REMOVE_USER_MESSAGE,
    id:id,
  };
};
