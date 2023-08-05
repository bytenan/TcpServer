#include "../source/server.hpp"

int main() {

    Socket srv;
    if (!srv.CreateServer(8888)) {
        return -1;
    }
    while (true) {
        int fd = srv.Accept();
        if (fd < 0) continue;
        Socket link(fd);
        char buf[1024] = { 0 };
        int n = link.Recv(buf, sizeof(buf) - 1);
        if (n < 0) {
            link.Close();
            continue;
        }
        DBG_LOG("%s", buf);
        link.Send(buf, n);
        link.Close();
    }
    srv.Close();
    return 0;
}