#include "ui_job.h"

namespace v8i {

DWORD WINAPI UiJob::ThreadMain(void* self) {
    auto* job = static_cast<UiJob*>(self);
    try {
        if (job->work_) job->work_();
    } catch (...) {
        // A throwing job still reports completion, so the UI leaves its busy
        // state instead of locking up.
    }
    PostMessageW(job->notify_, job->message_, (WPARAM)job->generation_, 0);
    return 0;
}

UiJob::~UiJob() { Stop(); }

bool UiJob::Start(HWND notify, UINT message, std::function<void()> work) {
    if (busy_ || !notify || !work) return false;

    work_ = std::move(work);
    notify_ = notify;
    message_ = message;
    ++generation_;

    thread_ = CreateThread(nullptr, 0, &UiJob::ThreadMain, this, 0, nullptr);
    if (!thread_) {
        work_ = nullptr;
        return false;
    }
    busy_ = true;
    return true;
}

bool UiJob::Finish(WPARAM wParam, UINT message) {
    if (!busy_ || message != message_) return false;
    if ((unsigned)wParam != generation_) return false;   // a stale completion
    // The worker posted as its last action: the join returns at once and, more
    // importantly, makes everything it wrote to the result visible here.
    Join();
    busy_ = false;
    return true;
}

void UiJob::Stop() {
    if (busy_) {
        Join();
        busy_ = false;
    } else if (thread_) {
        CloseHandle(thread_);
        thread_ = nullptr;
        work_ = nullptr;
    }
}

void UiJob::Join() {
    if (!thread_) return;
    WaitForSingleObject(thread_, INFINITE);
    CloseHandle(thread_);
    thread_ = nullptr;
    work_ = nullptr;
}

}  // namespace v8i
