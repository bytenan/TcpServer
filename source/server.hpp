#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <cstdio>
#include <cassert>
#include <ctime>
#include <cstring>

#define LOG(format, ...) do {                                                               \
    time_t t = time(nullptr);                                                               \
    struct tm *lt = localtime(&t);                                                          \
    char buf[128] = { 0 };                                                                  \
    strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", lt);                                \
    fprintf(stdout, "[%s] %s:%d: " format "\n", buf, __FILE__, __LINE__, ##__VA_ARGS__);    \
} while(0)

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