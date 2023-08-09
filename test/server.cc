#include "../source/server.hpp"

uint64_t conn_id = 0;
std::unordered_map<uint64_t, ConnectionPtr> conns;

void OnMessage(const ConnectionPtr &conn, Buffer *buf) {
    DBG_LOG("%s", buf->ReaderPosition());
    buf->MoveReaderOffset(buf->ReadableSize());
    std::string str = "hadhadwadadawda";
    conn->Send(str.c_str(), str.size());
    conn->Shutdown();
}
void OnClosed(const ConnectionPtr &conn) {
    conns.erase(conn->Id());
}
void OnConnected(const ConnectionPtr &conn) {
    DBG_LOG("NEW CONNECTION:%p", conn.get());
}

void Acceptor(EventLoop *loop, Channel *lisetn_channel) {
    int fd = accept(lisetn_channel->Fd(), nullptr, nullptr);
    if (fd < 0) {
        ERR_LOG("Acceptor failed!");
        return;
    }    
    ++conn_id;
    ConnectionPtr conn(new Connection(loop, conn_id, fd));
    conn->SetMessageCallBack(std::bind(OnMessage, std::placeholders::_1, std::placeholders::_2));
    conn->SetServerClosedCallBack(std::bind(OnClosed, std::placeholders::_1));
    conn->SetConnectedCallBack(std::bind(OnConnected, std::placeholders::_1));
    conn->EnableInactiveRelease(10);
    conn->Established();
    conns.insert(std::make_pair(conn_id, conn));
}

int main() {
    EventLoop loop;
    Socket srv;
    if (!srv.CreateServer(8888)) {
        ERR_LOG("CreateServer failed!");
        return -1;
    } 
    Channel channel(&loop, srv.Fd());
    channel.SetReadCallBack(std::bind(Acceptor, &loop, &channel));
    channel.EnableMonitorRead();
    loop.Run();
    srv.Close();
    return 0;
}