#include "../source/server.hpp"

void CloseHandler(Channel *channel) {
    DBG_LOG("close");
    channel->RemoveMonitor();
    delete channel;
}
void ReadHandler(Channel *channel) {
    char buf[1024] = { 0 };
    ssize_t n = recv(channel->Fd(), buf, sizeof(buf) - 1, 0);
    if (n < 0) CloseHandler(channel);
    DBG_LOG("%s", buf);
    channel->EnableMonitorWrite();
}
void WriteHandler(Channel *channel) {
    std::string msg = "哇哈哈";
    ssize_t n = send(channel->Fd(), msg.c_str(), msg.size(), 0);
    if (n < 0) CloseHandler(channel);
    channel->DisableMonitorWrite();
}
void ErrorHandler(Channel *channel) {
    CloseHandler(channel);
}
void AnyHandler(EventLoop *loop, Channel *channel, uint64_t timerid) {
    loop->TimerRefresh(timerid);
}

void Acceptor(EventLoop *loop, Channel *lisetn_channel) {
    int fd = accept(lisetn_channel->Fd(), nullptr, nullptr);
    if (fd < 0) {
        ERR_LOG("Acceptor failed!");
        return;
    }    

    uint64_t timerid = rand() % 100000;
    Channel *channel = new Channel(loop, fd);
    channel->SetReadCallBack(std::bind(ReadHandler, channel));
    channel->SetWriteCallBack(std::bind(WriteHandler, channel));
    channel->SetCloseCallBack(std::bind(CloseHandler, channel));
    channel->SetErrorCallBack(std::bind(ErrorHandler, channel));
    channel->SetAnyCallBack(std::bind(AnyHandler, loop, channel, timerid));
    loop->TimerAdd(timerid, 10, std::bind(CloseHandler, channel));
    channel->EnableMonitorRead();
}

int main() {
    srand(time(nullptr));
    Socket srv;
    if (!srv.CreateServer(8888)) {
        ERR_LOG("CreateServer failed!");
        return -1;
    }

    EventLoop loop;
    Channel channel(&loop, srv.Fd());
    channel.SetReadCallBack(std::bind(Acceptor, &loop, &channel));
    channel.EnableMonitorRead();
    loop.Run();
    srv.Close();
    return 0;
}