// --------------------------
// server.cpp
// Simple WhatsApp-like terminal chat server using Win32 IOCP + hiredis (sync)
// This is a prototype. Not production hardened. Build with MSVC, link ws2_32.lib, mswsock.lib, hiredis.lib
// Dependencies: hiredis (https://github.com/redis/hiredis)
// Protocol (text-based lines):
//  REGISTER <user> <pass>\n
//  LOGIN <user> <pass>\n
//  SEND <recipient> <message...>\n
//  LOGOUT\n
//  QUIT\n
// On LOGIN the server fetches pending messages from Redis list "msgs:<user>" using LRANGE and then DELs it

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <iostream>
#include <atomic>
#include <memory>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")

// Include hiredis (C library). Ensure header path and lib linked.
extern "C" {
#include <hiredis/hiredis.h>
}

// Minimal safe wrappers and helpers
struct ClientContext {
    SOCKET socket;
    std::string username; // empty if not logged in
    std::string recvBuf;
};

static std::mutex clients_m;
static std::map<std::string, std::shared_ptr<ClientContext>> onlineClients; // username -> context

// Redis connection (single shared, synchronous). For simplicity we serialize Redis calls with a mutex.
static std::mutex redis_m;
static redisContext* redis_ctx = nullptr;

bool redis_connect(const char* ip, int port){
    redis_ctx = redisConnect(ip, port);
    if(!redis_ctx || redis_ctx->err){
        if(redis_ctx) fprintf(stderr, "Redis error: %s\n", redis_ctx->errstr);
        return false;
    }
    return true;
}

// register
bool redis_register_user(const std::string &user, const std::string &pass){
    std::lock_guard<std::mutex> lk(redis_m);
    // store user:pass in hash users
    redisReply* r = (redisReply*)redisCommand(redis_ctx, "HSETNX users %s %s", user.c_str(), pass.c_str());
    if(!r) return false;
    bool ok = false;
    if(r->type == REDIS_REPLY_INTEGER){
        ok = (r->integer == 1);
    }
    freeReplyObject(r);
    return ok;
}

bool redis_check_login(const std::string &user, const std::string &pass){
    std::lock_guard<std::mutex> lk(redis_m);
    redisReply* r = (redisReply*)redisCommand(redis_ctx, "HGET users %s", user.c_str());
    if(!r) return false;
    bool ok = false;
    if(r->type == REDIS_REPLY_STRING){
        ok = (pass == r->str);
    }
    freeReplyObject(r);
    return ok;
}

// store message for recipient (list)
bool redis_store_message(const std::string &recipient, const std::string &msg){
    std::lock_guard<std::mutex> lk(redis_m);
    redisReply* r = (redisReply*)redisCommand(redis_ctx, "RPUSH msgs:%s %s", recipient.c_str(), msg.c_str());
    if(!r) return false;
    freeReplyObject(r);
    return true;
}

// fetch all pending messages for user and clear
std::vector<std::string> redis_fetch_pending(const std::string &user){
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lk(redis_m);
    redisReply* r = (redisReply*)redisCommand(redis_ctx, "LRANGE msgs:%s 0 -1", user.c_str());
    if(!r) return out;
    if(r->type == REDIS_REPLY_ARRAY){
        for(size_t i=0;i<r->elements;i++){
            redisReply* e = r->element[i];
            if(e->type == REDIS_REPLY_STRING) out.push_back(e->str);
        }
    }
    freeReplyObject(r);
    // delete list
    redisReply* d = (redisReply*)redisCommand(redis_ctx, "DEL msgs:%s", user.c_str());
    if(d) freeReplyObject(d);
    return out;
}

// Send data (blocking send) - in production you'd use WSASend with IOCP
bool send_text(SOCKET s, const std::string &line){
    std::string data = line + "\n";
    int total = 0;
    int len = (int)data.size();
    while(total < len){
        int sent = send(s, data.c_str()+total, len - total, 0);
        if(sent == SOCKET_ERROR) return false;
        total += sent;
    }
    return true;
}

// process a command line from client
void process_line(std::shared_ptr<ClientContext> ctx, const std::string &line){
    // tokenize
    if(line.empty()) return;
    std::string cmd;
    size_t pos = line.find(' ');
    if(pos==std::string::npos) { cmd = line; }
    else { cmd = line.substr(0,pos); }

    if(cmd == "REGISTER"){
        // REGISTER user pass
        std::string rest = (pos==std::string::npos) ? "" : line.substr(pos+1);
        size_t p2 = rest.find(' ');
        if(p2==std::string::npos){ send_text(ctx->socket, "ERROR usage: REGISTER <user> <pass>"); return; }
        std::string user = rest.substr(0,p2);
        std::string pass = rest.substr(p2+1);
        if(redis_register_user(user, pass)){
            send_text(ctx->socket, "OK registered");
        } else {
            send_text(ctx->socket, "ERROR user exists");
        }
        return;
    }
    if(cmd == "LOGIN"){
        std::string rest = (pos==std::string::npos) ? "" : line.substr(pos+1);
        size_t p2 = rest.find(' ');
        if(p2==std::string::npos){ send_text(ctx->socket, "ERROR usage: LOGIN <user> <pass>"); return; }
        std::string user = rest.substr(0,p2);
        std::string pass = rest.substr(p2+1);
        if(!redis_check_login(user, pass)){
            send_text(ctx->socket, "ERROR bad credentials");
            return;
        }
        {
            std::lock_guard<std::mutex> lk(clients_m);
            ctx->username = user;
            onlineClients[user] = ctx;
        }
        send_text(ctx->socket, "OK loggedin");
        // fetch pending messages
        auto msgs = redis_fetch_pending(user);
        if(!msgs.empty()){
            send_text(ctx->socket, "PENDING_START");
            for(auto &m: msgs) send_text(ctx->socket, std::string("MSG ")+m);
            send_text(ctx->socket, "PENDING_END");
        }
        return;
    }
    if(cmd == "SEND"){
        // SEND recipient message...
        if(ctx->username.empty()){ send_text(ctx->socket, "ERROR login first"); return; }
        std::string rest = (pos==std::string::npos) ? "" : line.substr(pos+1);
        size_t p2 = rest.find(' ');
        if(p2==std::string::npos){ send_text(ctx->socket, "ERROR usage: SEND <recipient> <message>"); return; }
        std::string recipient = rest.substr(0,p2);
        std::string msg = rest.substr(p2+1);
        // message format: FROM <sender> <message>
        std::string full = std::string("FROM ")+ctx->username+" "+msg;
        // if recipient online, deliver
        std::shared_ptr<ClientContext> rctx;
        {
            std::lock_guard<std::mutex> lk(clients_m);
            auto it = onlineClients.find(recipient);
            if(it!=onlineClients.end()) rctx = it->second;
        }
        if(rctx){
            send_text(rctx->socket, std::string("MSG ")+full);
            send_text(ctx->socket, "OK delivered");
        } else {
            // store in redis
            redis_store_message(recipient, full.c_str());
            send_text(ctx->socket, "OK stored_offline");
        }
        return;
    }
    if(cmd == "LOGOUT"){
        if(!ctx->username.empty()){
            std::lock_guard<std::mutex> lk(clients_m);
            onlineClients.erase(ctx->username);
            ctx->username.clear();
        }
        send_text(ctx->socket, "OK loggedout");
        return;
    }
    if(cmd == "QUIT"){
        send_text(ctx->socket, "BYE");
        // caller should close socket
        return;
    }
    send_text(ctx->socket, "ERROR unknown command");
}

// naive per-connection thread handler (instead of full IOCP for simplicity in prototype)
void connection_thread(SOCKET s){
    auto ctx = std::make_shared<ClientContext>();
    ctx->socket = s;

    char buf[1024];
    while(true){
        int n = recv(s, buf, sizeof(buf), 0);
        if(n <= 0) break;
        ctx->recvBuf.append(buf, buf+n);
        // process lines
        size_t pos;
        while((pos = ctx->recvBuf.find('\n')) != std::string::npos){
            std::string line = ctx->recvBuf.substr(0,pos);
            // strip CR
            if(!line.empty() && line.back()=='\r') line.pop_back();
            process_line(ctx, line);
            ctx->recvBuf.erase(0,pos+1);
        }
    }
    // cleanup
    if(!ctx->username.empty()){
        std::lock_guard<std::mutex> lk(clients_m);
        onlineClients.erase(ctx->username);
    }
    closesocket(s);
}

int main(){
    // init redis
    if(!redis_connect("127.0.0.1", 6379)){
        fprintf(stderr, "Failed to connect to Redis\n");
        return 1;
    }

    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if(iResult != 0){ fprintf(stderr, "WSAStartup failed: %d\n", iResult); return 1; }

    addrinfo hints = {}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    int rc = getaddrinfo(NULL, "9000", &hints, &result);
    if(rc != 0){ fprintf(stderr, "getaddrinfo failed: %d\n", rc); WSACleanup(); return 1; }

    SOCKET listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if(listenSocket == INVALID_SOCKET){ fprintf(stderr, "socket failed\n"); freeaddrinfo(result); WSACleanup(); return 1; }

    rc = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen);
    if(rc == SOCKET_ERROR){ fprintf(stderr, "bind failed\n"); closesocket(listenSocket); freeaddrinfo(result); WSACleanup(); return 1; }

    freeaddrinfo(result);

    if(listen(listenSocket, SOMAXCONN) == SOCKET_ERROR){ fprintf(stderr, "listen failed\n"); closesocket(listenSocket); WSACleanup(); return 1; }

    printf("Server listening on 0.0.0.0:9000\n");

    while(true){
        SOCKET client = accept(listenSocket, NULL, NULL);
        if(client == INVALID_SOCKET) { fprintf(stderr, "accept failed\n"); break; }
        // set to non-blocking? keep blocking for simplicity
        std::thread(connection_thread, client).detach();
    }

    closesocket(listenSocket);
    WSACleanup();
    if(redis_ctx) redisFree(redis_ctx);
    return 0;
}

// --------------------------
// BUILD & RUN
// 1. Install hiredis and build a lib you can link on Windows.
// 2. Compile server.cpp and client.cpp with MSVC (x64 or x86) and link Ws2_32.lib, Mswsock.lib, hiredis.lib
//    Example (Developer Command Prompt):
//    cl /EHsc /MD server.cpp /link Ws2_32.lib Mswsock.lib hiredis.lib
//    cl /EHsc /MD client.cpp /link Ws2_32.lib
// 3. Run Redis server locally (default 6379).
// 4. Start server.exe. Start multiple client.exe instances and use commands:
//    REGISTER alice pass
//    LOGIN alice pass
//    SEND bob Hello Bob!
//    LOGOUT
//    QUIT

// --------------------------
// NOTES
// - This is a straightforward prototype: to keep code short and readable it uses a per-connection thread rather
//   than implementing full asynchronous IOCP flow. Switching to IOCP primarily requires replacing the blocking
//   recv/send and per-thread model with overlapped operations and completion port worker threads.
// - Redis stores users in hash "users" and pending messages in lists "msgs:<username>".
// - On LOGIN the server pulls all messages from Redis (LRANGE) and sends them to the client, then deletes the list.
// - Authentication uses plaintext passwords stored in Redis: for a real system use hashing (bcrypt/argon2) and TLS.

