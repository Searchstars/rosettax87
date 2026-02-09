cmake_minimum_required(VERSION 3.10)

project(rosettax87)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(rosettax87
    loader/main.cpp
    loader/offset_finder.cpp
)

# We need to sign the binary with those entitlements to allow debugging without root
set(ENTITLEMENTS_FILE "${CMAKE_SOURCE_DIR}/entitlements.plist")
add_custom_command(TARGET rosettax87 POST_BUILD
    COMMAND codesign -s - --entitlements "${ENTITLEMENTS_FILE}" --force "$<TARGET_FILE:rosettax87>"
    COMMENT "Signing rosettax87 with entitlements"
)
