// client.cpp (STRUCT-BASED, MATCHES COMMON HEADERS)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <functional>
#include <cstring>
#include <chrono>

#include "../../common/protocol.h"

#pragma comment(lib, "Ws2_32.lib")

static std::atomic<bool> running{ true };
static HANDLE hConsole;

/* ================= Console helpers ================= */

enum Color {
    GREEN  = 10,
    CYAN   = 11,
    RED    = 12,
    YELLOW = 14,
    WHITE  = 15
};

void setColor(Color c) {
    SetConsoleTextAttribute(hConsole, c);
}

void printBanner() {
    setColor(CYAN);
    std::cout << "========================================\n";
    std::cout << "      TERMINAL CHAT CLIENT (BINARY)\n";
    std::cout << "========================================\n";

    setColor(YELLOW);
    std::cout << "Commands:\n";

    setColor(GREEN);
    std::cout << "  REGISTER <user> <pass>\n";
    std::cout << "  LOGIN    <user> <pass>\n";
    std::cout << "  SEND     <user> <message>\n";
    std::cout << "  LOGOUT\n";
    std::cout << "  QUIT\n";

    setColor(WHITE);
    std::cout << "----------------------------------------\n";
}

/* ================= Time helper ================= */

uint64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

/* ================= Network helpers ================= */

bool send_all(SOCKET s, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        int n = send(s, p, (int)len, 0);
        if (n <= 0) return false;
        p += n;
        len -= n;
    }
    return true;
}

bool send_packet(SOCKET s, MsgCode code, const void* body, uint32_t bodyLen) {
    MsgHeader hdr{};
    hdr.msgCode   = code;
    hdr.msgLength = sizeof(MsgHeader) + bodyLen;
    hdr.timestamp = now_ms();

    if (!send_all(s, &hdr, sizeof(hdr)))
        return false;

    if (bodyLen > 0 && body)
        return send_all(s, body, bodyLen);

    return true;
}

bool recv_all(SOCKET s, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        int n = recv(s, p, (int)len, 0);
        if (n <= 0) return false;
        p += n;
        len -= n;
    }
    return true;
}

/* ================= Receiver thread ================= */

void recv_loop(SOCKET s) {
    while (running) {
        MsgHeader hdr{};
        if (!recv_all(s, &hdr, sizeof(hdr)))
            break;

        uint32_t bodyLen = hdr.msgLength - sizeof(MsgHeader);
        std::string body;
        if (bodyLen > 0) {
            body.resize(bodyLen);
            if (!recv_all(s, &body[0], bodyLen))
                break;
        }

        setColor(CYAN);

        switch (hdr.msgCode) {
        case MSG_OK:
            std::cout << "<< OK\n";
            break;

        case MSG_ERROR: {
            auto* err = reinterpret_cast<const ErrorBody*>(body.data());
            std::cout << "<< ERROR: "
                      << std::string(err->errMsg, err->errLen) << "\n";
            break;
        }

        case MSG_CHAT: {
            auto* chat = reinterpret_cast<const ChatBody*>(body.data());
            std::cout << "<< [" << chat->from << "] "
                      << std::string(chat->msg, chat->msgLen) << "\n";
            break;
        }

        default:
            std::cout << "<< Unknown server message\n";
        }

        setColor(WHITE);
    }

    running = false;
    setColor(RED);
    std::cout << "Disconnected from server\n";
    setColor(WHITE);
}

/* ================= Command processors ================= */

void processRegister(SOCKET s) {
    RegisterBody b{};
    std::cin >> b.user >> b.pass;
    send_packet(s, MSG_REGISTER, &b, sizeof(b));
}

void processLogin(SOCKET s) {
    LoginBody b{};
    std::cin >> b.user >> b.pass;
    send_packet(s, MSG_LOGIN, &b, sizeof(b));
}

void processSend(SOCKET s) {
    std::string to, msg;
    std::cin >> to;
    std::getline(std::cin, msg);
    if (!msg.empty() && msg[0] == ' ')
        msg.erase(0, 1);

    uint32_t bodyLen = sizeof(SendBody) - 1 + (uint32_t)msg.size();
    char* buffer = new char[bodyLen];

    auto* b = reinterpret_cast<SendBody*>(buffer);
    std::memset(b, 0, sizeof(SendBody));
    std::strncpy(b->recipient, to.c_str(), sizeof(b->recipient) - 1);
    b->msgLen = (uint32_t)msg.size();
    std::memcpy(b->msg, msg.data(), msg.size());

    send_packet(s, MSG_SEND, buffer, bodyLen);
    delete[] buffer;
}

void processLogout(SOCKET s) {
    send_packet(s, MSG_LOGOUT, nullptr, 0);
}

void processQuit(SOCKET s) {
    send_packet(s, MSG_QUIT, nullptr, 0);
    running = false;
}

/* ================= Main ================= */

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage: client.exe <ip> <port>\n";
        return 1;
    }

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    printBanner();

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    getaddrinfo(argv[1], argv[2], &hints, &res);
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    std::thread t(recv_loop, sock);

    std::unordered_map<std::string, std::function<void()>> handlers {
        { "REGISTER", [&](){ processRegister(sock); } },
        { "LOGIN",    [&](){ processLogin(sock);    } },
        { "SEND",     [&](){ processSend(sock);     } },
        { "LOGOUT",   [&](){ processLogout(sock);   } },
        { "QUIT",     [&](){ processQuit(sock);     } }
    };

    while (running) {
        std::cout << "> ";
        std::string cmd;
        std::cin >> cmd;

        auto it = handlers.find(cmd);
        if (it != handlers.end()) {
            it->second();
        } else {
            setColor(RED);
            std::cout << "Unknown command\n";
            setColor(WHITE);
        }
    }

    shutdown(sock, SD_BOTH);
    closesocket(sock);
    t.join();
    WSACleanup();
    return 0;
}
