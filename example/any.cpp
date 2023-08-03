#include <iostream>
#include <typeinfo>
#include <string>
#include <cassert>

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
    Any &operator=(const T &val) { return Any(val).swap(*this); }
    Any &operator=(const Any &other) { return Any(other).swap(*this); }
    template<class T>
    T *get() {
        assert(typeid(T) == content_->type());
        return &(dynamic_cast<PlaceHolder<T> *>(content_)->val_);
    }
};

class Test {
public:
    Test() { std::cout << "构造" << std::endl; }
    Test(const Test& t) { std::cout << "拷贝" << std::endl; }
    ~Test() { std::cout << "析构" << std::endl; }
};

int main() {
    Any a;

    {
        Test t;
        a = t;
    }
    
    a = std::string("abcdefg");
    std::string *ps = a.get<std::string>();
    std::cout << *ps << std::endl;

    a = 10;
    int *pa = a.get<int>();
    std::cout << *pa << std::endl;
    return 0;
}