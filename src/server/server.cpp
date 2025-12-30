#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <mutex>
#include <map>
#include <memory>
#include <vector>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

extern "C" {
#include <hiredis/hiredis.h>
}

#include "../../common/protocol.h"
#include "server_logger.h"

/* ======================= Redis ======================= */

static std::mutex redis_m;
static redisContext* redis_ctx = nullptr;

bool redis_connect(const char* ip, int port) {
    redis_ctx = redisConnect(ip, port);
    if (!redis_ctx || redis_ctx->err) {
        log_error("Redis connection failed: %s",
                  redis_ctx ? redis_ctx->errstr : "null context");
        return false;
    }
    log_info("Connected to Redis at %s:%d", ip, port);
    return true;
}

bool redis_register_user(const char* user, const char* pass) {
    std::lock_guard<std::mutex> lk(redis_m);

    redisReply* r = (redisReply*)redisCommand(
        redis_ctx, "HSETNX users %s %s", user, pass
    );

    if (!r) {
        log_error("Redis HSETNX failed for user=%s", user);
        return false;
    }

    bool ok = (r->type == REDIS_REPLY_INTEGER && r->integer == 1);
    freeReplyObject(r);

    log_debug("Register user=%s result=%d", user, ok);
    return ok;
}

bool redis_check_login(const char* user, const char* pass) {
    std::lock_guard<std::mutex> lk(redis_m);

    redisReply* r = (redisReply*)redisCommand(
        redis_ctx, "HGET users %s", user
    );

    if (!r) {
        log_error("Redis HGET failed for user=%s", user);
        return false;
    }

    bool ok = (r->type == REDIS_REPLY_STRING &&
               strcmp(r->str, pass) == 0);

    freeReplyObject(r);

    log_debug("Login check user=%s result=%d", user, ok);
    return ok;
}

void redis_store_message(const char* recipient, const char* msg) {
    std::lock_guard<std::mutex> lk(redis_m);

    redisReply* r = (redisReply*)redisCommand(
        redis_ctx, "RPUSH msgs:%s %s", recipient, msg
    );

    if (!r) {
        log_error("Failed to store offline message for %s", recipient);
        return;
    }

    freeReplyObject(r);
    log_debug("Stored offline message for %s", recipient);
}

/* ======================= Client Context ======================= */

struct ClientContext {
    SOCKET socket;
    std::string username;
    std::vector<char> recvBuf;
};

static std::mutex clients_m;
static std::map<std::string, std::shared_ptr<ClientContext>> onlineClients;

/* ======================= Send Helpers ======================= */

bool send_packet(SOCKET s, MsgCode code, const void* body, uint32_t bodyLen) {
    MsgHeader hdr{};
    hdr.msgCode   = code;
    hdr.msgLength = sizeof(MsgHeader) + bodyLen;
    hdr.timestamp = GetTickCount64();

    std::vector<char> out(hdr.msgLength);
    memcpy(out.data(), &hdr, sizeof(hdr));
    if (bodyLen > 0) {
        memcpy(out.data() + sizeof(hdr), body, bodyLen);
    }

    size_t sent = 0;
    while (sent < out.size()) {
        int n = send(s, out.data() + sent,
                     (int)(out.size() - sent), 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

void send_ok(SOCKET s) {
    send_packet(s, MSG_OK, nullptr, 0);
}

void send_error(SOCKET s, const char* msg) {
    uint32_t len = (uint32_t)strlen(msg);
    std::vector<char> buf(sizeof(ErrorBody) - 1 + len);

    ErrorBody* b = (ErrorBody*)buf.data();
    b->errLen = len;
    memcpy(b->errMsg, msg, len);

    send_packet(s, MSG_ERROR, buf.data(), (uint32_t)buf.size());
}

/* ======================= Packet Extraction ======================= */

bool try_extract_packet(
    std::vector<char>& buf,
    MsgHeader& hdr,
    std::vector<char>& body
) {
    if (buf.size() < sizeof(MsgHeader))
        return false;

    memcpy(&hdr, buf.data(), sizeof(MsgHeader));

    if (buf.size() < hdr.msgLength)
        return false;

    uint32_t bodyLen = hdr.msgLength - sizeof(MsgHeader);
    body.resize(bodyLen);

    if (bodyLen > 0) {
        memcpy(body.data(),
               buf.data() + sizeof(MsgHeader),
               bodyLen);
    }

    buf.erase(buf.begin(), buf.begin() + hdr.msgLength);
    return true;
}

/* ======================= Handlers ======================= */

void handle_register(
    std::shared_ptr<ClientContext> ctx,
    const std::vector<char>& body
) {
    if (body.size() != sizeof(RegisterBody)) {
        send_error(ctx->socket, "Bad REGISTER packet");
        return;
    }

    const RegisterBody* b = (const RegisterBody*)body.data();

    if (redis_register_user(b->user, b->pass)) {
        send_ok(ctx->socket);
    } else {
        send_error(ctx->socket, "User exists");
    }
}

void handle_login(
    std::shared_ptr<ClientContext> ctx,
    const std::vector<char>& body
) {
    if (body.size() != sizeof(LoginBody)) {
        send_error(ctx->socket, "Bad LOGIN packet");
        return;
    }

    const LoginBody* b = (const LoginBody*)body.data();

    if (!redis_check_login(b->user, b->pass)) {
        send_error(ctx->socket, "Invalid credentials");
        return;
    }

    {
        std::lock_guard<std::mutex> lk(clients_m);
        ctx->username = b->user;
        onlineClients[ctx->username] = ctx;
    }

    log_info("User logged in: %s", ctx->username.c_str());
    send_ok(ctx->socket);
}

void handle_send(
    std::shared_ptr<ClientContext> ctx,
    const std::vector<char>& body
) {
    if (ctx->username.empty()) {
        send_error(ctx->socket, "Login required");
        return;
    }

    const SendBody* b = (const SendBody*)body.data();
    const char* msg = b->msg;

    log_debug("Message from %s to %s (len=%u)",
              ctx->username.c_str(),
              b->recipient,
              b->msgLen);

    std::shared_ptr<ClientContext> target;
    {
        std::lock_guard<std::mutex> lk(clients_m);
        auto it = onlineClients.find(b->recipient);
        if (it != onlineClients.end())
            target = it->second;
    }

    if (target) {
        send_packet(target->socket, MSG_CHAT,
                    body.data(), (uint32_t)body.size());
        send_ok(ctx->socket);
    } else {
        redis_store_message(b->recipient, msg);
        send_ok(ctx->socket);
    }
}

/* ======================= Dispatcher ======================= */

void dispatch_packet(
    std::shared_ptr<ClientContext> ctx,
    const MsgHeader& hdr,
    const std::vector<char>& body
) {
    log_debug("Dispatch msgCode=%u bodyLen=%u",
              hdr.msgCode, (uint32_t)body.size());

    switch (hdr.msgCode) {
    case MSG_REGISTER:
        handle_register(ctx, body);
        break;
    case MSG_LOGIN:
        handle_login(ctx, body);
        break;
    case MSG_SEND:
        handle_send(ctx, body);
        break;
    case MSG_LOGOUT:
        send_ok(ctx->socket);
        break;
    case MSG_QUIT:
        send_ok(ctx->socket);
        break;
    default:
        send_error(ctx->socket, "Unknown msgCode");
        break;
    }
}

/* ======================= Connection Thread ======================= */

void connection_thread(SOCKET s) {
    log_debug("Connection thread started (socket=%llu)",
              (unsigned long long)s);

    auto ctx = std::make_shared<ClientContext>();
    ctx->socket = s;
    ctx->recvBuf.reserve(8192);

    char tmp[2048];

    while (true) {
        int n = recv(s, tmp, sizeof(tmp), 0);
        if (n <= 0) break;

        ctx->recvBuf.insert(ctx->recvBuf.end(), tmp, tmp + n);

        MsgHeader hdr;
        std::vector<char> body;

        while (try_extract_packet(ctx->recvBuf, hdr, body)) {
            dispatch_packet(ctx, hdr, body);
        }
    }

    if (!ctx->username.empty()) {
        std::lock_guard<std::mutex> lk(clients_m);
        onlineClients.erase(ctx->username);
        log_info("User disconnected: %s", ctx->username.c_str());
    }

    log_debug("Socket closed: %llu", (unsigned long long)s);
    closesocket(s);
}

/* ======================= main ======================= */

int run_server() {
    logger_init();

    if (!redis_connect("127.0.0.1", 6379)) {
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_error("WSAStartup failed");
        return 1;
    }

    addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;

    getaddrinfo(nullptr, "9000", &hints, &res);

    SOCKET listenSock = socket(
        res->ai_family,
        res->ai_socktype,
        res->ai_protocol
    );

    bind(listenSock, res->ai_addr, (int)res->ai_addrlen);
    listen(listenSock, SOMAXCONN);
    freeaddrinfo(res);

    log_info("Server listening on port %d", 9000);

    while (true) {
        SOCKET client = accept(listenSock, nullptr, nullptr);
        if (client == INVALID_SOCKET)
            break;

        log_info("Client connected (socket=%llu)",
                 (unsigned long long)client);

        std::thread(connection_thread, client).detach();
    }

    closesocket(listenSock);
    WSACleanup();
    redisFree(redis_ctx);
    return 0;
}
