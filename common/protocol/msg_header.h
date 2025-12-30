#pragma once
#include <cstdint>

#pragma pack(push, 1)

/*
  Common header for ALL packets
  Total size: 14 bytes
*/
struct MsgHeader {
    uint16_t msgCode;     // Message type
    uint32_t msgLength;   // Total length: header + body
    uint64_t timestamp;   // Epoch milliseconds (sender side)
};

#pragma pack(pop)

static_assert(sizeof(MsgHeader) == 14, "MsgHeader size must be 14 bytes");
