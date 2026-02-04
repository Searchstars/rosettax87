cmake_minimum_required(VERSION 3.10)

project(rosettax87)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(rosettax87 loader/main.cpp loader/offset_finder.cpp)

# We need to sign the binary with those entitlements to allow debugging without root
set(ENTITLEMENTS_FILE "${CMAKE_SOURCE_DIR}/entitlements.plist")
add_custom_command(TARGET rosettax87 POST_BUILD
    COMMAND codesign -s - --entitlements "${ENTITLEMENTS_FILE}" --force "$<TARGET_FILE:rosettax87>"
    COMMENT "Signing rosettax87 with entitlements"
)

add_executable(libRuntimeRosettax87
    rosettaRuntime/main.cpp
    rosettaRuntime/X87Float80.cpp
    rosettaRuntime/X87StackRegister.cpp
    rosettaRuntime/X87State.cpp
    rosettaRuntime/X87.cpp
    rosettaRuntime/Export.cpp
    rosettaRuntime/Log.cpp
    rosettaRuntime/SIMDGuard.cpp
)

target_include_directories(libRuntimeRosettax87 PRIVATE
    rosettaRuntime
)

# Add ExternalProject module
include(ExternalProject)

# Create directories before CMake references them
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/deps/lib)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/deps/include)

set(OPTIMIZATION_FLAGS
    "-fvisibility=hidden"
    "-O3"
    "-funroll-loops"
    "-march=native"
    "-mtune=native"
    "-fomit-frame-pointer"
    "-mcpu=apple-m1"
    "-fno-builtin-sin"
    "-ftree-vectorize"
    "-fvectorize"
    "-finline-functions"
    "-fno-stack-protector"
    "-fno-exceptions"
    "-fno-unwind-tables"
    "-fno-asynchronous-unwind-tables"
)

string(REPLACE ";" " " OPTIMIZATION_FLAGS_STRING "${OPTIMIZATION_FLAGS}")

target_link_options(libRuntimeRosettax87 PRIVATE
    "-Wl,-no_compact_unwind"
    "-Wl,-no_pie"
    "-static"
    "-nostdlib"
    "-Wl,-segaddr,__TEXT,0x0"
    "-Wl,-segaddr,__DATA,0x20000"
    "-Wl,-pagezero_size,0x0"
    "-Wl,-headerpad,0"
    "-Wl,-e,_start"
    "-Wl,-segalign,10"
)

target_compile_options(libRuntimeRosettax87 PRIVATE
    ${OPTIMIZATION_FLAGS}
    "-flto"
)

set(HELPER_INLINE_C_OBJ "${CMAKE_BINARY_DIR}/helper_syscall_inline_c.o")

add_custom_command(
    OUTPUT "${HELPER_INLINE_C_OBJ}"
    COMMAND "${CMAKE_C_COMPILER}" -c "${CMAKE_SOURCE_DIR}/payload/helper_syscall_inline_c.c"
            -o "${HELPER_INLINE_C_OBJ}"
            -arch arm64
            -O2
            -ffreestanding
            -fno-builtin
            -fno-stack-protector
            -fno-asynchronous-unwind-tables
            -fno-unwind-tables
            -fno-exceptions
            -fno-vectorize
            -fno-slp-vectorize
            -ffixed-x9
            -ffixed-x10
            -ffixed-x11
            -ffixed-x12
            -ffixed-x13
            -ffixed-x14
            -ffixed-x15
            -ffixed-x18
    DEPENDS "${CMAKE_SOURCE_DIR}/payload/helper_syscall_inline_c.c"
    COMMENT "Building helper_syscall inline C blob"
)

add_custom_target(helper_inline_c_blob DEPENDS "${HELPER_INLINE_C_OBJ}")
add_dependencies(rosettax87 helper_inline_c_blob)
