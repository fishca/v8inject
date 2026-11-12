#include "test_runner.h"

// The unit tests have no framework around them: the runner prints the result
// and returns the number of failed tests as the exit code.
int main() {
    return v8i::test::RunAll() == 0 ? 0 : 1;
}
