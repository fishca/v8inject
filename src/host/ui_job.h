#pragma once
// One blocking job on a worker thread, for the GUI.
//
// Injecting, attaching and running a payload command take seconds each (15 s
// open timeout, 10-20 s command timeout), and the GUI used to do all of that on
// the thread that owns its window: the window stopped painting, reported "Не
// отвечает" and Windows offered to kill it (A80). A job runs on its own thread
// and reports back with a posted message; the owner disables its controls while
// `Busy()`.

#include <windows.h>
#include <functional>

namespace v8i {

class UiJob {
public:
    UiJob() = default;
    ~UiJob();
    UiJob(const UiJob&) = delete;
    UiJob& operator=(const UiJob&) = delete;

    // Runs `work` on a worker thread. When it returns, the job posts
    // PostMessage(notify, message, generation, 0). Returns false when a job is
    // already running or the thread could not be created.
    bool Start(HWND notify, UINT message, std::function<void()> work);

    // Called from the window procedure with the completion message: joins the
    // worker when the message belongs to this job and returns true.
    bool Finish(WPARAM wParam, UINT message);

    bool Busy() const { return busy_; }

    // Waits for a running job. Call it before the window - and with it the
    // client the job uses - goes away.
    void Stop();

private:
    static DWORD WINAPI ThreadMain(void* self);
    void Join();

    HWND notify_ = nullptr;
    UINT message_ = 0;
    HANDLE thread_ = nullptr;
    unsigned generation_ = 0;
    bool busy_ = false;
    std::function<void()> work_;
};

}  // namespace v8i
