#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <mutex>
#include <thread>
#include <memory>
#include <typeinfo>
#include <cstdio>
#include <cassert>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
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
        if (0 == len) return;
        assert(len <= ReadableSize());
        reader_offset_ += len;
    }
    // 写偏移向后移动
    void MoveWriterOffset(uint64_t len) {
        if (0 == len) return;
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
        if (0 == len) return;
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
        if (0 == len) return;
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
        if (0 == len) return 0;
        ssize_t n = recv(sockfd_, buf, len, flags);
        if (n < 0) {
            // EAGAIN 表示当前sockfd_的接受缓冲区没有数据了，在非阻塞情况下去读的话会出现这个错误
            // EINTR  表示当前sockfd_的阻塞等待被信号打断了
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
        if (0 == len) return 0;
        ssize_t n = send(sockfd_, buf, len, flags);
        if (n < 0) {
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
        int flag = fcntl(sockfd_, F_GETFL, 0); 
        if (flag < 0) {
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
    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0", bool is_block = false) {
        if (!Create()) return false;
        if(!SetReuseAddr()) return false;
        if (!Bind(ip, port)) return false;
        if (!Listen()) return false;
        if (is_block) if (!SetNonBlock()) return false;
        return true;
    }
private:
    int sockfd_;
};

class EventLoop;
using EventCallBack = std::function<void()>;
class Channel {
public:
    Channel(EventLoop *loop, int fd) : fd_(fd), events_(0), revents_(0), loop_(loop) {}
    int Fd() { return fd_; }
    uint32_t Events() { return events_; }
    void SetREvents(uint32_t revents) { revents_ = revents; }
    void SetReadCallBack(const EventCallBack &read_cb) { read_cb_ = read_cb; }
    void SetWriteCallBack(const EventCallBack &write_cb) { write_cb_ = write_cb; }
    void SetErrorCallBack(const EventCallBack &error_cb) { error_cb_ = error_cb; }
    void SetCloseCallBack(const EventCallBack &close_cb) { close_cb_ = close_cb; }
    void SetAnyEventCallBack(const EventCallBack &any_event_cb) { any_event_cb_ = any_event_cb; }
    // 读事件是否被监控
    bool IsMonitorRead() { return events_ & EPOLLIN; }
    // 写事件是否被监控
    bool IsMonitorWrite() { return events_ & EPOLLOUT; }
    // 读事件启动监控
    void EnableMonitorRead() { events_ |= EPOLLIN; UpdateMonitor(); }
    // 写事件启动监控
    void EnableMonitorWrite() { events_ |= EPOLLOUT; UpdateMonitor(); }
    // 读事件关闭监控
    void DisableMonitorRead() { events_ &= ~EPOLLIN; UpdateMonitor(); }
    // 写事件关闭监控
    void DisableMonitorWrite() { events_ &= ~EPOLLOUT; UpdateMonitor(); }
    // 关闭所有事件的监控
    void DisableMonitorAll() { events_ = 0; UpdateMonitor(); }
    // 移除事件监控
    void RemoveMonitor();
    // 更新事件监控
    void UpdateMonitor();
    // 事件处理
    void EventHandler() {
        if ((revents_ & EPOLLIN) || (revents_ & EPOLLRDHUP) || (revents_ & EPOLLPRI)) {
            if (read_cb_) read_cb_();
        }
        // 有可能会释放连接的事件，每次只处理一个
        if (revents_ & EPOLLOUT) {
            if (write_cb_) write_cb_();
        } else if (revents_ & EPOLLERR) {
            if (error_cb_) error_cb_();
        } else if (revents_ & EPOLLHUP) {
            if (close_cb_) close_cb_();
        }
        if (any_event_cb_) any_event_cb_();
    }
private:
    int fd_;    // 被监控的文件描述符
    uint32_t events_;   // 当前需要监控的事件
    uint32_t revents_;  // 当前连续触发的事件
    EventLoop *loop_;
    EventCallBack read_cb_;     //读事件触发的回调函数
    EventCallBack write_cb_;    //写事件触发的回调函数
    EventCallBack error_cb_;    //错误事件触发的回调函数
    EventCallBack close_cb_;    //连接断开事件触发的回调函数
    EventCallBack any_event_cb_;//任意事件触发的回调函数
};

#define MAX_EPOLLEVENTS 1024
class Poller {
public:
    Poller() : epfd_(-1) {
        epfd_ = epoll_create(MAX_EPOLLEVENTS);
        if (epfd_ < 0) {
            ERR_LOG("EPOLL CREATE FAILED!");
            abort();
        }
    }
    ~Poller() { 
        if (-1 != epfd_) {
            close(epfd_);
            epfd_ = -1;
        }
    }
    // 更新事件监控
    void UpdateEvent(Channel *channel) {
        if (HasChannel(channel)) {
            // 当描述符已被监控时，仅修改描述符对应的监控事件
            Update(channel, EPOLL_CTL_MOD);
        } else {
            // 当描述符未被监控时，将描述符对应的监控事件进行监控
            channels_.insert(std::make_pair(channel->Fd(), channel));
            Update(channel, EPOLL_CTL_ADD);
        }
    }
    // 移除事件监控
    void RemoveEvent(Channel *channel) {
        if (HasChannel(channel)) {
            channels_.erase(channel->Fd());
        }
        Update(channel, EPOLL_CTL_DEL);
    }
    // 开始监控
    void Poll(std::vector<Channel *> *active) {
        int fds = epoll_wait(epfd_, events_, MAX_EPOLLEVENTS, -1);
        if (fds < 0) {
            if (errno == EINTR) return;
            ERR_LOG("EPOLL WAIT ERROR:%s\n", strerror(errno));
            abort();
        }
        for (int i = 0; i < fds; ++i) {
            auto it = channels_.find(events_[i].data.fd);
            assert(channels_.end() != it);
            it->second->SetREvents(events_[i].events);
            active->push_back(it->second);
        }
    }
private:
    // 真正操作描述符以及监控事件的函数
    void Update(Channel *channel, int op) {
        struct epoll_event ev;
        ev.data.fd = channel->Fd();
        ev.events = channel->Events();
        if (epoll_ctl(epfd_, op, channel->Fd(), &ev) < 0) {
            ERR_LOG("EPOLLCTL FAILED!");
        }
    }
    // 判断描述符是否被监控
    bool HasChannel(Channel *channel) {
        return channels_.end() == channels_.find(channel->Fd()) ? false : true;
    }
private:
    int epfd_;
    struct epoll_event events_[MAX_EPOLLEVENTS];
    std::unordered_map<int, Channel *> channels_;
};

using TaskCallBack = std::function<void()>;
using ReleaseCallBack = std::function<void()>;
class TimerTask {
public:
    TimerTask(uint64_t id, uint32_t timeout, const TaskCallBack &task_cb, const ReleaseCallBack &release_cb) 
        : id_(id), timeout_(timeout), is_cancel_(false), task_cb_(task_cb), release_cb_(release_cb) {}
    ~TimerTask() { 
        if (!is_cancel_) task_cb_(); 
        release_cb_(); 
    }
    void Cancel() { is_cancel_ = true; }
    uint32_t timeout() { return timeout_; }
private:
    uint64_t id_;       // 定时器对象ID
    uint32_t timeout_;  // 定时器对象的超时时间
    bool is_cancel_;    // false表示任务不取消，true表示任务被取消
    TaskCallBack task_cb_;  // 定时器对象要执行的任务
    ReleaseCallBack release_cb_;  // 用于删除TimingWheel中的指向定时器对象的weakptr
};

using TimerWeakPtr = std::weak_ptr<TimerTask>;
using TimerSharedPtr = std::shared_ptr<TimerTask>;
class TimeWheel {
public:
    TimeWheel(EventLoop *loop)
        : tick_(0)
        , capacity_(60)
        , wheel_(capacity_)
        , loop_(loop)
        , timerfd_(InitTimerFd())
        , timerfd_channel_(new Channel(loop_, timerfd_)) {
        timerfd_channel_->SetReadCallBack(std::bind(&TimeWheel::OnTime, this));
        timerfd_channel_->EnableMonitorRead();
    }
    void TimerAdd(uint64_t id, uint32_t timeout, const TaskCallBack &task_cb);
    void TimerRefresh(uint64_t id);
    void TimerCancel(uint64_t id);
    bool HasTimer(uint64_t id) { return timers_.end() == timers_.find(id) ? false : true; } 
private:
    void TimerRemove(uint64_t id) {
        auto it = timers_.find(id);
        if (timers_.end() != it) timers_.erase(it);
    }
    static int InitTimerFd() {
        int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (timerfd < 0) {
            ERR_LOG("TIMERFD CREATE FAILED!");
            abort();
        }
        struct itimerspec itime;
        itime.it_value.tv_sec = 1;
        itime.it_value.tv_nsec = 0;//第一次超时时间为1s后
        itime.it_interval.tv_sec = 1; 
        itime.it_interval.tv_nsec = 0; //第一次超时后，每次超时的间隔时
        timerfd_settime(timerfd, 0, &itime, nullptr);
        return timerfd;
    }
    int ReadTimeFd() {
        uint64_t times;
        int ret = read(timerfd_, &times, sizeof(times));
        if (ret < 0) {
            ERR_LOG("READ TIMEFD FAILED!");
            abort();
        }
        return times;
    }
    void Run() {
        tick_  = (tick_ + 1) % capacity_;
        wheel_[tick_].clear();
    }
    void OnTime() {
        int times = ReadTimeFd();
        for (int i = 0; i < times; ++i) Run();
    }
    void TimerAddInLoop(uint64_t id, uint32_t timeout, const TaskCallBack &task_cb) {
        TimerSharedPtr tsp(new TimerTask(id, timeout, task_cb, std::bind(&TimeWheel::TimerRemove, this, id)));
        timers_[id] = TimerWeakPtr(tsp);
        int pos = (tick_ + timeout) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void TimerRefreshInLoop(uint64_t id) {
        auto it = timers_.find(id);
        if (timers_.end() == it) return;
        TimerSharedPtr tsp(it->second.lock());
        int pos = (tick_ + tsp->timeout()) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void TimerCancelInLoop(uint64_t id) {
        auto it = timers_.find(id);
        if (timers_.end() == it) return;
        TimerSharedPtr tsp(it->second.lock());
        if (tsp) tsp->Cancel();
    }
private:
    int tick_;      // 秒针，秒针指向哪里，就释放哪里的智能指针，就相当于执行哪里的任务
    int capacity_;  // 时间轮的总容量，这里定为60，所以也就定义了一个轮子。相当于表盘里的秒针转一圈
    std::vector<std::vector<TimerSharedPtr>> wheel_;    // 轮子，保存定时器对象的sharedptr，当ptr被释放并且其中的计时器减到0时，定时器对象里的任务就会被执行
    std::unordered_map<uint64_t, TimerWeakPtr> timers_; // 保存所有的定时器对象的weakptr，当需要使用sharedptr时，直接从这里取出weakptr，进而取出sharedptr
    EventLoop *loop_;
    int timerfd_;
    std::unique_ptr<Channel> timerfd_channel_;
};

using Functor = std::function<void()>;
class EventLoop {
public:
    EventLoop() : thread_id_(std::this_thread::get_id())
                , event_fd_(CreateEventFd())
                , event_fd_channel_(new Channel(this, event_fd_))
                , time_wheel_(this)  {
        event_fd_channel_->SetReadCallBack(std::bind(&EventLoop::ReadEventFd, this));
        event_fd_channel_->EnableMonitorRead();
    }
    // 进行事件监控，处理就绪事件，处理任务队列中的任务
    void Run() {
        while (true) {
            std::vector<Channel *> active;
            poller_.Poll(&active);
            for (auto &channel : active) channel->EventHandler();
            ExecTasks();
        }
    }
    // 判断当前线程是否是EventLoop线程
    bool IsInLoop() { return thread_id_ == std::this_thread::get_id(); }
    // 当前线程必须在EventLoop线程
    void AssertInLoop() { assert(thread_id_ == std::this_thread::get_id()); }
    // 对于将要执行的任务，若在EventLoop线程则直接执行，否则压入任务队列。
    void RunInLoop(const Functor &cb) {
        if (IsInLoop()) return cb();
        PushTask(cb);
    }
    void PushTask(const Functor &cb) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            tasks_.push_back(cb);
        }
        WriteEventFd();
    }
    void UpdateEvent(Channel *channel) { return poller_.UpdateEvent(channel); }
    void RemoveEvent(Channel *channel) { return poller_.RemoveEvent(channel); }
    void TimerAdd(uint64_t id, uint32_t timeout, const TaskCallBack &task_cb) { time_wheel_.TimerAdd(id, timeout, task_cb); }
    void TimerRefresh(uint64_t id) { time_wheel_.TimerRefresh(id); }
    void TimerCancel(uint64_t id) { time_wheel_.TimerCancel(id); }
    bool HasTimer(uint64_t id) { return time_wheel_.HasTimer(id); }
private:
    static int CreateEventFd() {
        int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (fd < 0) {
            ERR_LOG("CREATE EVENTFD FAILED!");
            abort();
        }
        return fd;
    }
    void ReadEventFd() {
        uint64_t val = 0;
        int n = read(event_fd_, &val, sizeof(val));
        if (n < 0) {
            if (EINTR == errno || EAGAIN == errno) return;
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
    }
    void WriteEventFd() {
        uint64_t val = 1;
        int n = write(event_fd_, &val, sizeof(val));
        if (n < 0) {
            if (EINTR == errno || EAGAIN == errno) return;
            ERR_LOG("WRITE EVENTFD FAILED!");
            abort();
        }
    }
    void ExecTasks() {
        std::vector<Functor> tasks;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            tasks_.swap(tasks);
        }
        for (auto &task : tasks) task();
    }
private:
    std::thread::id thread_id_;
    Poller poller_;
    int event_fd_;
    std::unique_ptr<Channel> event_fd_channel_;
    std::mutex mutex_;
    std::vector<Functor> tasks_;
    TimeWheel time_wheel_;
};

class Any {
private:
    class Holder {
    public:
        virtual ~Holder() {}
        virtual const std::type_info &type() = 0;
        virtual Holder *clone() = 0;
    };
    template<class T>
    class PlaceHolder : public Holder {
    public:
        PlaceHolder(const T &val) : val_(val) {}
        virtual const std::type_info &type() { return typeid(T); }
        virtual Holder *clone() { return new PlaceHolder(val_); }
    public:
        T val_;
    };
    Holder *content_;
public:
    Any() : content_(nullptr) {}
    template<class T>
    Any(const T &val) : content_(new PlaceHolder<T>(val)) {}
    Any(const Any &other) : content_(nullptr == other.content_ ? nullptr : other.content_->clone()) {}
    ~Any() { delete content_; }
    Any &swap(Any &other) {
        std::swap(content_, other.content_);
        return *this;
    }
    template<class T>
    Any &operator=(const T &val) {
        Any(val).swap(*this);
        return *this;
    }
    Any &operator=(const Any &other) {
        Any(other).swap(*this);
        return *this;
    }
    template<class T>
    T *get() {
        assert(typeid(T) == content_->type());
        return &(dynamic_cast<PlaceHolder<T> *>(content_)->val_);
    }
};

class Connection;
typedef enum { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING } ConnStatu;
using ConnectionPtr = std::shared_ptr<Connection>;
using ConnectedCallBack = std::function<void(const ConnectionPtr &)>;
using MessageCallBack = std::function<void(const ConnectionPtr &, Buffer *)>;
using ClosedCallBack = std::function<void(const ConnectionPtr &)>;
using AnyEventCallBack = std::function<void(const ConnectionPtr &)>;
class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(EventLoop *loop, uint64_t conn_id, int sockfd)
        : conn_id_(conn_id)
        , is_enable_inactive_release_(false)
        , sockfd_(sockfd)
        , loop_(loop)
        , statu_(CONNECTING)
        , socket_(sockfd_) 
        , channel_(loop, sockfd_) {
        channel_.SetReadCallBack(std::bind(&Connection::ReadHandler, this));
        channel_.SetWriteCallBack(std::bind(&Connection::WriteHandler, this));
        channel_.SetErrorCallBack(std::bind(&Connection::ErrorHandler, this));
        channel_.SetCloseCallBack(std::bind(&Connection::CloseHandler, this));
        channel_.SetAnyEventCallBack(std::bind(&Connection::AnyEventHandler, this));
    }
    ~Connection() { DBG_LOG("RELEASE CONNECTION:%p", this); }
    uint64_t Id() { return conn_id_; }
    uint64_t Fd() { return sockfd_; }
    bool IsConnected() { return CONNECTED == statu_; }
    Any *Context() { return &context_; }
    void SetContext(const Any &context) { context_ = context; }
    void SetConnectedCallBack(const ConnectedCallBack &connected_cb) { connected_cb_ = connected_cb; }
    void SetMessageCallBack(const MessageCallBack &message_cb) { message_cb_ = message_cb; }
    void SetClosedCallBack(const ClosedCallBack &closed_cb) { closed_cb_ = closed_cb; }
    void SetAnyEventCallBack(const AnyEventCallBack &any_event_cb) { any_event_cb_ = any_event_cb; }
    void SetServerClosedCallBack(const ClosedCallBack &server_closed_cb) { server_closed_cb_ = server_closed_cb; }
    // 连接建立就绪后，进行channel回调设置，启动读监控
    void Established() { loop_->RunInLoop(std::bind(&Connection::EstablishedInLoop, this)); }
    // 将数据写入输出缓冲区，启动写监控
    void Send(const char *data, size_t len) {
        Buffer buf;
        buf.WriteAndPushOffset(data, len);
        loop_->RunInLoop(std::bind(&Connection::SendInLoop, this, std::move(buf)));
    }
    // 给组件使用者提供的接口，用于关闭连接（但实际不关闭，该接口只检验缓冲区内是否还有数据待处理）
    void Shutdown() { loop_->RunInLoop(std::bind(&Connection::ShutdownInLoop, this)); }
    void Release() { loop_->PushTask(std::bind(&Connection::ReleaseInLoop, this)); }
    // 启动sec时间内的非活跃连接销毁
    void EnableInactiveRelease(int sec) { loop_->RunInLoop(std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec)); }
    // 关闭非活跃连接销毁
    void DisableInactiveRelease() { loop_->RunInLoop(std::bind(&Connection::DisableInactiveReleaseInLoop, this)); }
    // 升级协议---非线程安全，这个接口必须在EventLoop线程立即执行，防备新的事件触发后，协议还未升级。
    void Upgrade(const Any &context, const ConnectedCallBack &connected_cb, const MessageCallBack &message_cb, 
                const ClosedCallBack &closed_cb, const AnyEventCallBack &any_event_cb) {
        loop_->AssertInLoop();
        loop_->RunInLoop(std::bind(&Connection::UpgradeInLoop, this, context, connected_cb, message_cb, closed_cb, any_event_cb));
    }
private:
    void ReadHandler() {
        char buf[65536] = { 0 };
        ssize_t n = socket_.RecvNonBlock(buf, 65535);
        if (n < 0) return ShutdownInLoop();
        in_buffer_.WriteAndPushOffset(buf, n);
        if (in_buffer_.ReadableSize() > 0) message_cb_(shared_from_this(), &in_buffer_);
    }
    void WriteHandler() {
        ssize_t n = socket_.SendNonBlock(out_buffer_.ReaderPosition(), out_buffer_.ReadableSize());
        if (n < 0) {
            if (in_buffer_.ReadableSize() > 0) message_cb_(shared_from_this(), &in_buffer_);
            Release();
        }
        out_buffer_.MoveReaderOffset(n);
        if (out_buffer_.ReadableSize() == 0) {
            channel_.DisableMonitorWrite();
            if (DISCONNECTING == statu_) Release();
        }
    }
    void CloseHandler() {
        if (in_buffer_.ReadableSize() > 0) message_cb_(shared_from_this(), &in_buffer_);
        Release();
    }
    void ErrorHandler() { CloseHandler(); }
    void AnyEventHandler() {
        if (is_enable_inactive_release_) loop_->TimerRefresh(conn_id_); 
        if (any_event_cb_) any_event_cb_(shared_from_this()); 
    }
    void EstablishedInLoop() {
        assert(CONNECTING == statu_);
        statu_ = CONNECTED;
        channel_.EnableMonitorRead();
        if (connected_cb_) connected_cb_(shared_from_this());
    }
    void SendInLoop(Buffer &buf) {
        if (DISCONNECTED == statu_) return;
        out_buffer_.WriteBufferAndPushOffset(buf);
        if (!channel_.IsMonitorWrite()) channel_.EnableMonitorWrite();
    }
    void ShutdownInLoop() {
        statu_ = DISCONNECTING;
        if (in_buffer_.ReadableSize() > 0) 
            if (message_cb_) message_cb_(shared_from_this(), &in_buffer_);
        if (out_buffer_.ReadableSize() > 0) 
            if (!channel_.IsMonitorWrite()) channel_.EnableMonitorWrite();
        if (out_buffer_.ReadableSize() == 0) 
            Release();
    }
    // 真正关闭连接的接口
    void ReleaseInLoop() {
        statu_ = DISCONNECTED;
        channel_.RemoveMonitor();
        socket_.Close();
        if (loop_->HasTimer(conn_id_)) DisableInactiveReleaseInLoop();
        if (closed_cb_) closed_cb_(shared_from_this());
        if (server_closed_cb_) server_closed_cb_(shared_from_this());
    }
    void EnableInactiveReleaseInLoop(int sec) {
        is_enable_inactive_release_ = true;
        if (loop_->HasTimer(conn_id_)) 
            loop_->TimerRefresh(conn_id_);
        else 
            loop_->TimerAdd(conn_id_, sec, std::bind(&Connection::Release, this));
    }
    void DisableInactiveReleaseInLoop() {
        is_enable_inactive_release_ = false;
        if (loop_->HasTimer(conn_id_)) loop_->TimerCancel(conn_id_);
    }
    void UpgradeInLoop(const Any &context, const ConnectedCallBack &connected_cb, const MessageCallBack &message_cb, 
                const ClosedCallBack &closed_cb, const AnyEventCallBack &any_event_cb) {
        context_ = context;
        connected_cb_ = connected_cb;
        message_cb_ = message_cb;
        closed_cb_ = closed_cb;
        any_event_cb_ = any_event_cb;
    }
private:
    uint64_t conn_id_;  // 连接的ID
    bool is_enable_inactive_release_;   // 连接是否开启“非活跃销毁”
    int sockfd_;        // 连接关联的文件描述符
    EventLoop *loop_;   // 连接关联的EventLoop
    ConnStatu statu_;   // 连接所处的状态
    Channel channel_;   // 连接的事件管理
    Socket socket_;     // 套接字操作管理
    Buffer in_buffer_;  // 输入缓冲区
    Buffer out_buffer_; // 输出缓冲区
    Any context_;       // 上下文
    ConnectedCallBack connected_cb_;    
    MessageCallBack message_cb_;        
    ClosedCallBack closed_cb_;
    AnyEventCallBack any_event_cb_;
    ClosedCallBack server_closed_cb_;
};

void Channel::RemoveMonitor() { loop_->RemoveEvent(this); }
void Channel::UpdateMonitor() { loop_->UpdateEvent(this); }
void TimeWheel::TimerAdd(uint64_t id, uint32_t timeout, const TaskCallBack &task_cb) {
    loop_->RunInLoop(std::bind(&TimeWheel::TimerAddInLoop, this, id, timeout, task_cb));
}
void TimeWheel::TimerRefresh(uint64_t id) {
    loop_->RunInLoop(std::bind(&TimeWheel::TimerRefreshInLoop, this, id));
}
void TimeWheel::TimerCancel(uint64_t id) {
    loop_->RunInLoop(std::bind(&TimeWheel::TimerCancelInLoop, this, id));
}