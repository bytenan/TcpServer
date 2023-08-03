#include <iostream>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <unistd.h>

using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;
class TimerTask {
public:
    TimerTask(uint64_t id, uint32_t timeout, const TaskFunc &task_cb, const ReleaseFunc &release_cb) 
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
    TaskFunc task_cb_;  // 定时器对象要执行的任务
    ReleaseFunc release_cb_;  // 用于删除TimingWheel中的指向定时器对象的weakptr
};

using TimerWeakPtr = std::weak_ptr<TimerTask>;
using TimerSharedPtr = std::shared_ptr<TimerTask>;
class TimeWheel {
public:
    TimeWheel() : tick_(0), capacity_(60), wheel_(capacity_) {}
    void TimerAdd(uint64_t id, uint32_t timeout, TaskFunc task_cb) {
        TimerSharedPtr tsp(new TimerTask(id, timeout, task_cb, std::bind(&TimeWheel::TimerRemove, this, id)));
        timers_[id] = TimerWeakPtr(tsp);
        int pos = (tick_ + timeout) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void TimerRefresh(uint64_t id) {
        auto it = timers_.find(id);
        if (timers_.end() == it) return;
        TimerSharedPtr tsp(it->second.lock());
        int pos = (tick_ + tsp->timeout()) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void TimerCancel(uint64_t id) {
        auto it = timers_.find(id);
        if (timers_.end() == it) return;
        TimerSharedPtr tsp(it->second.lock());
        if (tsp) tsp->Cancel();
    }
    void Run() {
        tick_  = (tick_ + 1) % capacity_;
        wheel_[tick_].clear();
    }
private:
    void TimerRemove(uint64_t id) {
        auto it = timers_.find(id);
        if (timers_.end() != it) timers_.erase(it);
    }
private:
    int tick_;      // 秒针，秒针指向哪里，就释放哪里的智能指针，就相当于执行哪里的任务
    int capacity_;  // 时间轮的总容量，这里定为60，所以也就定义了一个轮子。相当于表盘里的秒针转一圈
    std::vector<std::vector<TimerSharedPtr>> wheel_;    // 轮子，保存定时器对象的sharedptr，当ptr被释放并且其中的计时器减到0时，定时器对象里的任务就会被执行
    std::unordered_map<uint64_t, TimerWeakPtr> timers_; // 保存所有的定时器对象的weakptr，当需要使用sharedptr时，直接从这里取出weakptr，进而取出sharedptr
};

class Test {
public:
    Test() { std::cout << __FUNCTION__ << std::endl; }
    ~Test() { std::cout << __FUNCTION__ << std::endl; }
};

void TestDel(Test *pt) { delete pt; }

int main() {
    Test *pt = new Test();
    TimeWheel tw; 
    tw.TimerAdd(777, 5, std::bind(TestDel, pt));
    for (int i = 0; i < 5; ++i) {
        sleep(1);
        tw.TimerRefresh(777);
        tw.Run();
        std::cout << "刷新了任务，重新在5秒后执行销毁任务" << std::endl;
    }
    tw.TimerCancel(777);
    while (true) {
        sleep(1);
        std::cout << "-----------------------------" << std::endl;
        tw.Run();
    }
    return 0; 
}