#pragma once
// A minimal test runner.
//
// The project builds hermetically and offline (Capstone is vendored, nothing
// is fetched), so no external framework: a test is a plain function, CHECK
// records a failure and lets the test continue, REQUIRE stops it.
//
//   V8I_TEST(NameOfTheTest) {
//       CHECK(2 + 2 == 4);
//       REQUIRE(FindSomething() != nullptr);
//   }
//
// The tests are registered before main() runs and are executed in the
// registration order. The process exit code is the number of failed tests,
// so CTest sees a failure without parsing the output.

#include <cstdio>
#include <string>

namespace v8i {
namespace test {

using TestFn = void (*)();

// Registers a test. Called from a static initializer, so it must not throw
// and must not depend on the order of the translation units.
int Register(const char* name, TestFn fn);

// Sends the transcript to a file as well as to the console. The CI keeps the
// artifact of the build: when a test fails on a runner, the log says which
// test failed and why, while the console output only shows an exit code.
void SetLogFile(FILE* log);

// Records a failed check.
void Fail(const char* file, int line, const std::string& what);

// The check itself: counts the check, reports it when it fails and tells the
// caller whether it passed (REQUIRE needs that to stop the test).
bool CheckTrue(bool ok, const char* file, int line, const std::string& what);

// Text for the failure message: numbers and strings are printed, anything
// else falls back to a placeholder. The integer overloads are spelled out
// one by one: on a 32-bit build "unsigned int" and "unsigned long long"
// would both be candidates for the same argument.
std::string Text(int v);
std::string Text(unsigned int v);
std::string Text(long long v);
std::string Text(unsigned long long v);
std::string Text(const std::string& v);
std::string Text(const std::wstring& v);

template <typename A, typename B>
void CheckEq(const A& a, const B& b, const char* file, int line, const char* expr) {
    if (a == b) return;
    Fail(file, line, std::string(expr) + " (" + Text(a) + " != " + Text(b) + ")");
}

template <typename A, typename B>
void CheckNe(const A& a, const B& b, const char* file, int line, const char* expr) {
    if (!(a == b)) return;
    Fail(file, line, std::string(expr) + " (both " + Text(a) + ")");
}

// Runs every registered test and returns the number of failed ones.
int RunAll();

}  // namespace test
}  // namespace v8i

#define V8I_TEST(name)                                                        \
    static void name();                                                      \
    static const int name##_registered = v8i::test::Register(#name, name);   \
    static void name()

#define CHECK(cond) v8i::test::CheckTrue((cond), __FILE__, __LINE__, #cond)

#define CHECK_EQ(a, b) v8i::test::CheckEq((a), (b), __FILE__, __LINE__, #a " == " #b)

#define CHECK_NE(a, b) v8i::test::CheckNe((a), (b), __FILE__, __LINE__, #a " != " #b)

#define REQUIRE(cond)                                                        \
    do {                                                                     \
        if (!v8i::test::CheckTrue((cond), __FILE__, __LINE__, #cond))         \
            return;                                                          \
    } while (0)
