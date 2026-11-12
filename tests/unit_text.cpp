// The text helpers: UTF-8 <-> UTF-16, JSON escaping, number parsing.
//
// These were private copies in five modules, so a bug in one of them was
// invisible: the command line accepted "-1" as an address, and a \uXXXX
// escape was cut in half.

#include "json_check.h"
#include "test_runner.h"

#include "v8inject/text.h"

using namespace v8i;
using namespace v8i::test;

namespace {

// "Привет" in UTF-8.
const char kCyrillic[] = "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82";

}  // namespace

V8I_TEST(Text_Utf8RoundTrip) {
    CHECK_EQ(Utf8ToWide(""), std::wstring());
    CHECK_EQ(Utf8ToWide("abc"), std::wstring(L"abc"));
    CHECK_EQ(Utf8ToWide(kCyrillic), std::wstring(L"Привет"));

    CHECK_EQ(WideToUtf8(L""), std::string());
    CHECK_EQ(WideToUtf8(L"abc"), std::string("abc"));
    CHECK_EQ(WideToUtf8(L"Привет"), std::string(kCyrillic));

    // Both directions.
    CHECK_EQ(WideToUtf8(Utf8ToWide(kCyrillic)), std::string(kCyrillic));
    CHECK_EQ(Utf8ToWide(WideToUtf8(L"Привет")), std::wstring(L"Привет"));
}

V8I_TEST(Text_NarrowAscii) {
    CHECK_EQ(NarrowAscii(L"core85.dll"), std::string("core85.dll"));
    CHECK_EQ(NarrowAscii(L""), std::string());
    // A non-ASCII character becomes a placeholder, not half a character.
    CHECK_EQ(NarrowAscii(L"Проверка"), std::string("????????"));
    CHECK_EQ(NarrowAscii(L"aПb"), std::string("a?b"));
}

V8I_TEST(Text_JsonEscape) {
    CHECK_EQ(JsonEscape("plain"), std::string("plain"));
    CHECK_EQ(JsonEscape("say \"hi\""), std::string("say \\\"hi\\\""));
    CHECK_EQ(JsonEscape("back\\slash"), std::string("back\\\\slash"));
    CHECK_EQ(JsonEscape("line\nbreak"), std::string("line\\nbreak"));
    CHECK_EQ(JsonEscape("tab\there"), std::string("tab\\there"));
    CHECK_EQ(JsonEscape(std::string("bell\x07")), std::string("bell\\u0007"));

    // Cyrillic is already UTF-8 and stays as it is.
    CHECK_EQ(JsonEscape(kCyrillic), std::string(kCyrillic));

    // The wide variant converts first.
    CHECK_EQ(JsonEscapeWide(L"П"), std::string("\xD0\x9F"));
    CHECK_EQ(JsonEscapeWide(L"a\"b"), std::string("a\\\"b"));
}

V8I_TEST(Text_JsonEscapeKeepsTheAnswerValid) {
    // A hook name with a quote must not break the whole answer.
    const std::string json = "{\"name\":\"" + JsonEscape("имя \"с\" кавычкой") + "\"}";
    std::string err;
    CHECK(JsonValid(json, &err));
}

V8I_TEST(Text_ParseNumber) {
    uintptr_t v = 0;

    CHECK(ParseNumber(L"0", &v));
    CHECK_EQ(v, (uintptr_t)0);
    CHECK(ParseNumber(L"42", &v));
    CHECK_EQ(v, (uintptr_t)42);
    CHECK(ParseNumber(L"0x1A2B", &v));
    CHECK_EQ(v, (uintptr_t)0x1A2B);
    CHECK(ParseNumber(L"0X1a2b", &v));
    CHECK_EQ(v, (uintptr_t)0x1A2B);
    CHECK(ParseNumber(L"  7  ", &v));
    CHECK_EQ(v, (uintptr_t)7);

    // A leading zero is decimal, not octal: "010" used to be eight.
    CHECK(ParseNumber(L"010", &v));
    CHECK_EQ(v, (uintptr_t)10);

    // Garbage is rejected. The old parser accepted "-1" and turned it into a
    // huge address.
    CHECK(!ParseNumber(L"", &v));
    CHECK(!ParseNumber(L"-1", &v));
    CHECK(!ParseNumber(L"+1", &v));
    CHECK(!ParseNumber(L"0x", &v));
    CHECK(!ParseNumber(L"12abc", &v));
    CHECK(!ParseNumber(L"0xZZ", &v));
    CHECK(!ParseNumber(L"   ", &v));
    CHECK(!ParseNumber(L"1 2", &v));

    // A null pointer is not a number.
    CHECK(!ParseNumber((const wchar_t*)nullptr, &v));
}

V8I_TEST(Text_UnescapeStrValue) {
    CHECK_EQ(UnescapeStrValue("plain"), std::wstring(L"plain"));
    CHECK_EQ(UnescapeStrValue("a\\\"b"), std::wstring(L"a\"b"));
    CHECK_EQ(UnescapeStrValue("a\\\\b"), std::wstring(L"a\\b"));
    CHECK_EQ(UnescapeStrValue("a\\nb"), std::wstring(L"a\nb"));
    CHECK_EQ(UnescapeStrValue("a\\rb"), std::wstring(L"a\rb"));
    CHECK_EQ(UnescapeStrValue("a\\tb"), std::wstring(L"a\tb"));

    // A BMP escape.
    CHECK_EQ(UnescapeStrValue("\\u041F\\u0440"), std::wstring(L"Пр"));
    // A surrogate pair: one code point above the BMP.
    CHECK_EQ(UnescapeStrValue("\\uD83D\\uDE00"), std::wstring(L"\xD83D\xDE00"));

    // A broken escape is left alone instead of producing rubbish.
    CHECK_EQ(UnescapeStrValue("\\uZZZZ"), std::wstring(L"\\uZZZZ"));
    CHECK_EQ(UnescapeStrValue("\\u041"), std::wstring(L"\\u041"));
}
