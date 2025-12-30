#pragma once
#include <cstdint>

#pragma pack(push, 1)

/* ---------- REGISTER / LOGIN ---------- */
struct RegisterBody {
    char user[32];
    char pass[32];
};

struct LoginBody {
    char user[32];
    char pass[32];
};

/* ---------- SEND MESSAGE ---------- */
/*
  msgLen bytes follow immediately after this struct
*/
struct SendBody {
    char recipient[32];
    uint32_t msgLen;
    char msg[1];   // flexible array
};

/* ---------- SERVER RESPONSES ---------- */
struct ErrorBody {
    uint32_t errLen;
    char errMsg[1];
};

struct ChatBody {
    char from[32];
    uint32_t msgLen;
    char msg[1];
};

#pragma pack(pop)
