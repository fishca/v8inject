# Capstone, x86 only.
#
# Vendored rather than fetched: the build must stay hermetic and offline, and we
# only ever disassemble x86/x64 — the other architectures are 30 MB of dead
# weight. Capstone is BSD-3-Clause (see LICENSE.TXT in the upstream tree).

set(CAPSTONE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone)

add_library(capstone STATIC
    ${CAPSTONE_DIR}/cs.c
    ${CAPSTONE_DIR}/MCInst.c
    ${CAPSTONE_DIR}/MCInstrDesc.c
    ${CAPSTONE_DIR}/MCRegisterInfo.c
    ${CAPSTONE_DIR}/SStream.c
    ${CAPSTONE_DIR}/Mapping.c
    ${CAPSTONE_DIR}/utils.c
    ${CAPSTONE_DIR}/arch/X86/X86Disassembler.c
    ${CAPSTONE_DIR}/arch/X86/X86DisassemblerDecoder.c
    ${CAPSTONE_DIR}/arch/X86/X86InstPrinterCommon.c
    ${CAPSTONE_DIR}/arch/X86/X86ATTInstPrinter.c
    ${CAPSTONE_DIR}/arch/X86/X86IntelInstPrinter.c
    ${CAPSTONE_DIR}/arch/X86/X86Mapping.c
    ${CAPSTONE_DIR}/arch/X86/X86Module.c
)

target_include_directories(capstone PUBLIC
    ${CAPSTONE_DIR}/include
    ${CAPSTONE_DIR}
)
target_compile_definitions(capstone PUBLIC
    CAPSTONE_HAS_X86=1
    CAPSTONE_X86_SUPPORT=1
)

# Capstone is C89-era code and spews warnings under /W4; keep them quiet but
# leave our own translation units at the project's warning level.
if(MSVC)
    target_compile_options(capstone PRIVATE /W0)
endif()
