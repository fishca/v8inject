#pragma once

#ifdef V8I_PAYLOAD_EXPORTS
#  define V8I_API extern "C" __declspec(dllexport)
#else
#  define V8I_API extern "C" __declspec(dllimport)
#endif

#define V8I_CALL __stdcall
