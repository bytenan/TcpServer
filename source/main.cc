#include "server.hpp"

void TestLog() {
    LOG("hello world");
    LOG("haha--%d", 10);
    std::string str = "nihao";
    LOG("%s", str.c_str());
}

void TestBuffer() {
    // Buffer buf;
    // std::cout << buf.ReadableSize() << std::endl;
    // buf.WriteStringAndPushOffset("hello world");
    // std::cout << buf.ReadableSize() << std::endl;
    // std::cout << buf.ReadAsStringAndPushOffset(buf.ReadableSize()) << std::endl;
    // std::cout << buf.ReadableSize() << std::endl;

    Buffer buf;
    for (int i = 0; i < 200; ++i) {
        std::string str = "hello world" + std::to_string(i) + "\n";
        buf.WriteStringAndPushOffset(str);
    }
    // Buffer newbuf;
    // newbuf.WriteBufferAndPushOffset(buf);
    // std::cout << newbuf.ReadAsStringAndPushOffset(newbuf.ReadableSize()) << std::endl;
    // std::cout << newbuf.ReadableSize() << std::endl;

    while (buf.ReadableSize() > 0) {
        std::cout << buf.GetLineAndPushOffset() << std::endl;
    }
}

int main() {

    // TestLog();
    TestBuffer();

    return 0;
}