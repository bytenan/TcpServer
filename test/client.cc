#include "../source/server.hpp"

int main() {
    Socket cli;
    cli.CreateClient(8888, "127.0.0.1");
    std::string msg = "hello world";
    cli.Send(msg.c_str(), msg.size());
    char buf[1024] = { 0 };
    cli.Recv(buf, sizeof(buf) - 1);
    DBG_LOG("%s", buf);
    return 0;
}