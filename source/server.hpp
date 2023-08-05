#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <cstdio>
#include <cassert>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL INF

#define LOG(level, format, ...) do {                                                        \
    if (level < LOG_LEVEL) break;                                                           \
    time_t t = time(nullptr);                                                               \
    struct tm *lt = localtime(&t);                                                          \
    char temp[64] = { 0 };                                                                  \
    strftime(temp, sizeof(temp) - 1, "%Y-%m-%d %H:%M:%S", lt);                              \
    fprintf(stdout, "[%s] %s:%d: " format "\n", temp, __FILE__, __LINE__, ##__VA_ARGS__);   \
} while(0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)

#define BUFFER_DEFAULT_SIZE 1024
class Buffer {
public:
    Buffer() : buffer_(BUFFER_DEFAULT_SIZE), reader_offset_(0), writer_offset_(0) {}
    // 获取读位置
    char *ReaderPosition() { return &(*buffer_.begin()) + reader_offset_; }
    // 获取写位置
    char *WriterPosition() { return &(*buffer_.begin()) + writer_offset_; }
    // 获取可读大小
    uint64_t ReadableSize() { return writer_offset_ - reader_offset_; }
    // 获取头部可写大小（读偏移往前位置）
    uint64_t HeadWritableSize() { return reader_offset_; }
    // 获取尾部可写大小（写偏移往后位置）
    uint64_t TailWritableSize() { return buffer_.size() - writer_offset_; }
    // 读偏移向后移动
    void MoveReaderOffset(uint64_t len) {
        assert(len <= ReadableSize());
        reader_offset_ += len;
    }
    // 写偏移向后移动
    void MoveWriterOffset(uint64_t len) {
        assert(len <= TailWritableSize());
        writer_offset_ += len;
    }
    // 确保可写空间足够
    void EnsureWritableSpaceEnough(uint64_t len) {
        if (len <= TailWritableSize()) { 
            // 当len小于缓冲区尾部可写大小，直接返回即可。
            return;
        } else if (len <= HeadWritableSize() + TailWritableSize()) { 
            // 当len大于缓冲区尾部可写大小，但是小于缓冲区头部和尾部可写大小之和时，将缓冲区内部的可读数据移动到缓冲区头部即可。
            std::copy(ReaderPosition(), WriterPosition(), buffer_.begin());
            writer_offset_ = ReadableSize();
            reader_offset_ = 0;
        } else {
            // 当len大于缓冲区头部和尾部可写大小之和时，无需移动可读数据，直接在缓冲区尾部扩容即可。
            buffer_.resize(writer_offset_ + len);
        }
    }
    // 写入数据
    void Write(const void *data, uint64_t len) {
        EnsureWritableSpaceEnough(len);
        std::copy((const char *)data, (const char *)data + len, WriterPosition());
    }
    void WriteAndPushOffset(const void *data, uint64_t len) {
        Write(data, len);
        MoveWriterOffset(len);
    }
    void WriteString(const std::string &data) {
        Write(data.c_str(), data.size());
    }
    void WriteStringAndPushOffset(const std::string &data) {
        WriteString(data);
        MoveWriterOffset(data.size());
    }
    void WriteBuffer(Buffer &data) {
        Write(data.ReaderPosition(), data.ReadableSize());
    }
    void WriteBufferAndPushOffset(Buffer &data) {
        WriteBuffer(data);
        MoveWriterOffset(data.ReadableSize());
    }
    // 读取数据
    void Read(void *buf, uint64_t len) {
        assert(len <= ReadableSize());
        std::copy(ReaderPosition(), ReaderPosition() + len, (char *)buf);
    }
    void ReadAndPushOffset(void *buf, uint64_t len) {
        Read(buf, len);
        MoveReaderOffset(len);
    }
    std::string ReadAsString(uint64_t len) {
        assert(len <= ReadableSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str;
    }
    std::string ReadAsStringAndPushOffset(uint64_t len) {
        assert(len <= ReadableSize());
        std::string str = ReadAsString(len);
        MoveReaderOffset(len);
        return str;
    }
    std::string GetLine() {
        char *pos = (char *)memchr(ReaderPosition(), '\n', ReadableSize());
        if (nullptr == pos) return "";
        return ReadAsString(pos - ReaderPosition() + 1);
    }
    std::string GetLineAndPushOffset() {
        std::string str = GetLine();
        MoveReaderOffset(str.size());
        return str;
    }
    // 清空缓冲区
    void Clear() { reader_offset_ = writer_offset_ = 0; }
private:
    std::vector<char> buffer_;   
    uint64_t reader_offset_; 
    uint64_t writer_offset_; 
};

#define BACKLOG_SIZE 64
class Socket {
public:
    Socket() : sockfd_(-1) {}
    Socket(int sockfd) : sockfd_(sockfd) {}
    ~Socket() { Close(); }
    int Fd() { return sockfd_; }
    bool Create() {
        sockfd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockfd_ < 0) {
            ERR_LOG("SOCKET CREATE FAILED!");
            return false;
        }
        return true;
    }
    bool Bind(const std::string &ip, uint16_t port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t addrlen = sizeof addr;
        if (bind(sockfd_, (struct sockaddr *)&addr, addrlen) < 0) {
            ERR_LOG("SOCKET BIND FAILED!");
            return false;
        }
        return true;
    }
    bool Listen(int backlog = BACKLOG_SIZE) {
        if (listen(sockfd_, backlog) < 0) {
            ERR_LOG("SOCKET LISTEN FAILED!");
            return false;
        }
        return true;
    }
    int Accept() {
        int fd = accept(sockfd_, nullptr, nullptr);
        if (fd < 0) {
            ERR_LOG("SOCKET ACCEPT FAILED!");
            return -1;
        }
        return fd;
    }
    bool Connect(const std::string &ip, uint16_t port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t addrlen = sizeof addr;
        if (connect(sockfd_, (struct sockaddr *)&addr, addrlen) < 0) {
            ERR_LOG("SOCKET CONNECT FAILED!");
            return false;
        }
        return true;
    }
    ssize_t Recv(void *buf, size_t len, int flags = 0) {
        ssize_t n = recv(sockfd_, buf, len, flags);
        if (n <= 0) {
            if (EAGAIN == errno || EINTR == errno) {
                return 0;
            }
            ERR_LOG("SOCKET RECV FAILED!");
            return -1;
        }
        return n;
    }
    ssize_t RecvNonBlock(void *buf, size_t len) {
        return Recv(buf, len, MSG_DONTWAIT);
    }
    ssize_t Send(const void *buf, size_t len, int flags = 0) {
        ssize_t n = send(sockfd_, buf, len, flags);
        if (n <= 0) {
            if (EAGAIN == errno || EINTR == errno) {
                return 0;
            }
            ERR_LOG("SOCKET SEND FAILED!");
            return -1;
        }
        return n;
    }
    ssize_t SendNonBlock(void *buf, size_t len) {
        return Send(buf, len, MSG_DONTWAIT);
    }
    void Close() {
        if (-1 != sockfd_) {
            close(sockfd_);
            sockfd_ = -1;
        }
    }
    bool SetNonBlock() {
        int flag; 
        if (flag = fcntl(sockfd_, F_GETFL, 0) < 0) {
            ERR_LOG("SOCKET SETNONBLOCK FAILED!");
            return false;
        }
        if (fcntl(sockfd_, F_SETFL, flag | O_NONBLOCK) < 0) {
            ERR_LOG("SOCKET SETNONBLOCK FAILED!");
            return false;
        }
        return true;
    }
    bool SetReuseAddr() {
        int val = 1;
        if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (void *)&val, sizeof (val)) < 0) {
            ERR_LOG("SOCKET SETREUSEADDR FAILED!");
            return false;
        }
        return true;
    }
    bool CreateClient(uint16_t port, const std::string &ip) {
        if (!Create()) return false;
        if (!Connect(ip, port)) return false;
        return true;
    }
    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0", bool is_block = true) {
        if (!Create()) return false;
        if (!is_block) if (!SetNonBlock()) return false;
        if (!Bind(ip, port)) return false;
        if (!Listen()) return false;
        if(!SetReuseAddr()) return false;
        return true;
    }
private:
    int sockfd_;
};

using EventCallBack = std::function<void()>;
class Channel {
public:
    Channel(int fd) : fd_(fd), events_(0), revents_(0) {}
    int Fd() { return fd_; }
    uint32_t Events() { return events_; }
    void SetREvents(uint32_t revents) { revents_ = revents; }
    void SetReadCallBack(const EventCallBack &read_cb) { read_cb_ = read_cb; }
    void SetWriteCallBack(const EventCallBack & write_cb) { write_cb_ = write_cb; }
    void SetErrorCallBack(const EventCallBack & error_cb) { error_cb_ = error_cb; }
    void SetCloseCallBack(const EventCallBack & close_cb) { close_cb_ = close_cb; }
    void SetAnyCallBack(const EventCallBack & any_cb) { any_cb_ = any_cb; }
    // 读事件是否被监控
    bool IsMonitorRead() { return events_ & EPOLLIN; }
    // 写事件是否被监控
    bool IsMonitorWrite() { return events_ & EPOLLOUT; }
    // 读事件启动监控
    void EnableMonitorRead() { events_ |= EPOLLIN;     /*TODO:后边还需添加到EventLoop的事件监控中*/ }
    // 写事件启动监控
    void EnableMonitorWrite() { events_ |= EPOLLOUT;   /*TODO:后边还需添加到EventLoop的事件监控中*/ }
    // 读事件关闭监控
    void DisableMonitorRead() { events_ &= ~EPOLLIN;   /*TODO:后边还需修改到EventLoop的事件监控中*/ }
    // 写事件关闭监控
    void DisableMonitorWrite() { events_ &= ~EPOLLOUT; /*TODO:后边还需修改到EventLoop的事件监控中*/ }
    // 关闭所有事件的监控
    void DisableMonitorAll() { events_ = 0; }
    // 移除监控
    void RemoveMonitor() { /*TODO:后边需要调用EventLoop的接口来移除监控*/ }
    // 事件处理
    void EventHandler() {
        if ((revents_ & EPOLLIN) || (revents_ & EPOLLRDHUP) || (revents_ & EPOLLPRI)) {
            if (read_cb_) read_cb_();
            if (any_cb_) any_cb_();
        }
        // 有可能会释放连接的事件，每次只处理一个
        if (revents_ & EPOLLOUT) {
            if (write_cb_) write_cb_();
            if (any_cb_) any_cb_();
        } else if (revents_ & EPOLLERR) {
            if (any_cb_) any_cb_();
            if (error_cb_) error_cb_();
        } else if (revents_ & EPOLLHUP) {
            if (any_cb_) any_cb_();
            if (close_cb_) close_cb_();
        }
    }
private:
    int fd_;    // 被监控的文件描述符
    uint32_t events_;   // 当前需要监控的事件
    uint32_t revents_;  // 当前连续触发的事件
    EventCallBack read_cb_;     //读事件触发的回调函数
    EventCallBack write_cb_;    //写事件触发的回调函数
    EventCallBack error_cb_;    //错误事件触发的回调函数
    EventCallBack close_cb_;    //连接断开事件触发的回调函数
    EventCallBack any_cb_;      //任意事件触发的回调函数
};