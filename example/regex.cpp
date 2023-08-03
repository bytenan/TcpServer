#include <iostream>
#include <string>
#include <regex>

void func(const std::string &s, const std::regex &e) {
    std::smatch sm;
    if (std::regex_match(s, sm, e)) {
        for (auto &s : sm) {
            std::cout << s << std::endl;
        }
    }
}

int main() {
    
    std::string http_request_head1 = "GET /images/1.png?username=nanshao&pasword=123456 HTTP/1.1";// 暂时不写\r\n
    std::regex e1("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE).*");// 取出请求方法
    std::regex e2("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE) ([^?]*).*");// 取出请求方法、uri
    std::regex e3("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE) ([^?]*)\\?(.*) .*");// 取出请求方法、uri、表单信息
    std::regex e4("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE) ([^?]*)\\?(.*) (HTTP/1\\.[01])");// 取出请求方法、uri、表单信息、协议版本

    std::string http_request_head2 = "GET /images/1.png?username=nanshao&pasword=123456 HTTP/1.1\r\n";// 写上\r\n
    std::regex e5("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE) ([^?]*)\\?(.*) (HTTP/1\\.[01])(?:\n|\r\n)?");// 有时间隔符可能没有所以加?，有时间隔符可能仅写\n所以选择\n|\r\n

    std::string http_request_head3 = "GET /images/1.png HTTP/1.1\r\n";// 去掉表单信息
    std::regex e6("(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?");// 表单信息有可能有有可能没有
    func(http_request_head3, e6);
    
    return 0;
}