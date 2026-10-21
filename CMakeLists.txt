cmake_minimum_required(VERSION 3.20)
project(v8inject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "v8inject: Windows-only project")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(V8I_ARCH "x86")
else()
    set(V8I_ARCH "x64")
endif()
message(STATUS "v8inject: building for ${V8I_ARCH}")

# Placement that works for both single-config and multi-config generators.
function(v8i_set_output target)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/${V8I_ARCH}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/${V8I_ARCH}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/${V8I_ARCH}"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin/${V8I_ARCH}"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin/${V8I_ARCH}"
    )
endfunction()

add_library(v8i_common STATIC
    src/common/diag.cpp
    src/common/pe_utils.cpp
    src/common/typeinfo_utils.cpp
    src/common/report.cpp
)
target_include_directories(v8i_common PUBLIC include)
target_compile_definitions(v8i_common PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    V8I_ARCH_${V8I_ARCH}
)
target_link_libraries(v8i_common PUBLIC oleaut32 ole32)

# ---- payload: loaded INTO the target process ----
add_library(v8i_payload SHARED
    src/payload/dllmain.cpp
    src/payload/objects.cpp
    src/payload/v8i_export.cpp
)
target_compile_definitions(v8i_payload PRIVATE V8I_PAYLOAD_EXPORTS)
target_link_libraries(v8i_payload PRIVATE v8i_common)
set_target_properties(v8i_payload PROPERTIES
    OUTPUT_NAME "v8i_payload"
    PREFIX ""
)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # x86 stdcall decoration would hide the export from GetProcAddress.
    target_sources(v8i_payload PRIVATE src/payload/v8i_payload32.def)
endif()
v8i_set_output(v8i_payload)
# no .def file: exports are declared with __declspec(dllexport) in v8i_export.h

# ---- host + cli: runs OUTSIDE the target process ----
add_executable(v8inject
    src/cli/main.cpp
    src/host/injector.cpp
    src/host/client.cpp
)
target_link_libraries(v8inject PRIVATE v8i_common psapi)
v8i_set_output(v8inject)

# ---- smoke test ----
enable_testing()
add_test(NAME cli_help COMMAND v8inject --help)
