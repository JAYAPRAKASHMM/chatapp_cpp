#pragma once

#include "msg_header.h"
#include "msg_body.h"

/*
  Message codes
*/
enum MsgCode : uint16_t {
    /* client -> server */
    MSG_REGISTER = 1,
    MSG_LOGIN    = 2,
    MSG_SEND     = 3,
    MSG_LOGOUT   = 4,
    MSG_QUIT     = 5,

    /* server -> client */
    MSG_OK       = 100,
    MSG_ERROR    = 101,
    MSG_CHAT     = 102
};
