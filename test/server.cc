#include "../source/server.hpp"

void CloseHandler(Channel *channel) {
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
void AnyHandler(Channel *channel) {
    DBG_LOG("有一个事件");
}

void Acceptor(Poller *poller, Channel *lisetn_channel) {
    int fd = accept(lisetn_channel->Fd(), nullptr, nullptr);
    if (fd < 0) {
        ERR_LOG("Acceptor failed!");
        return;
    }    
    Channel *channel = new Channel(poller, fd);
    channel->SetReadCallBack(std::bind(ReadHandler, channel));
    channel->SetWriteCallBack(std::bind(WriteHandler, channel));
    channel->SetCloseCallBack(std::bind(CloseHandler, channel));
    channel->SetErrorCallBack(std::bind(ErrorHandler, channel));
    channel->SetAnyCallBack(std::bind(AnyHandler, channel));
    channel->EnableMonitorRead();
}

int main() {

    Socket srv;
    if (!srv.CreateServer(8888)) {
        ERR_LOG("CreateServer failed!");
        return -1;
    }

    Poller poller;
    Channel channel(&poller, srv.Fd());
    channel.SetReadCallBack(std::bind(Acceptor, &poller, &channel));
    channel.EnableMonitorRead();

    while (true) {
        std::vector<Channel *> active;
        poller.Poll(&active);
        for (auto &a : active) {
            a->EventHandler();
        }
    }
    srv.Close();
    return 0;
}