#pragma once

#include <string>

namespace v8i {
namespace platform {

// True when the payload runs inside a 1C:Enterprise Configurator.
bool V8iIsTargetProcess();

// Arms the WH_CBT / CreateWindowExW early path before the command loop starts.
bool V8iArmEarlySubscribe();

// Designer commands of the Config group; every reply is JSON.
std::string CmdCommandToJson(const std::wstring& args);
std::string CmdCmd85ToJson(const std::wstring& args);
std::string CmdInfoToJson(const std::wstring& args);
std::string CmdFramesToJson(const std::wstring& args);
std::string CmdExports85ToJson(const std::wstring& args);

}  // namespace platform
}  // namespace v8i
