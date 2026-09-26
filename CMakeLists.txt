# 3.28 for EXCLUDE_FROM_ALL in FetchContent_Declare, which keeps Zydis's own
# tools and tests out of the default build.
cmake_minimum_required(VERSION 3.28)

project(pe-mcp VERSION 1.0.0 LANGUAGES C CXX)

if(NOT MSVC)
    message(FATAL_ERROR "pe-mcp is developed and tested with MSVC. The core is portable C++20; only this build is MSVC-only.")
endif()

get_property(_pm_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _pm_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Static CRT, so pe-mcp.exe runs on a clean Windows with no VC++ redistributable.
# An MCP client that launches a server which then fails to start shows only
# "connection closed", so a missing DLL is the worst kind of failure here.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(PEMCP_BUILD_TESTS "Build the unit tests" ON)
option(PEMCP_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)

include(FetchContent)

# ---------------------------------------------------------------------------
# Dependencies, all pinned (see THIRD_PARTY_NOTICES.md)
# ---------------------------------------------------------------------------

# Zydis: the x86/x64 decoder (MIT). The same commit Pointer Lab and Signature
# Lab pin, so the three tools disassemble identically.
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS      OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN        OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc # v4.1.1
    EXCLUDE_FROM_ALL
)

# nlohmann/json: the JSON reader and writer (MIT). The single header from the
# v3.11.3 release, pinned by hash, so no git history is fetched for one file.
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    URL_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
    DOWNLOAD_NO_EXTRACT TRUE
)

FetchContent_MakeAvailable(zydis nlohmann_json)

# The header lands at <source dir>/json.hpp. It is copied under nlohmann/ so
# the code includes it by its usual name, and the directory is SYSTEM so the
# first-party /W4 /WX does not apply to a 25 000-line third-party header.
configure_file(${nlohmann_json_SOURCE_DIR}/json.hpp ${CMAKE_CURRENT_BINARY_DIR}/json-include/nlohmann/json.hpp COPYONLY)
add_library(pemcp_json INTERFACE)
target_include_directories(pemcp_json SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/json-include)

# sigscan: vendored single header (MIT), see third_party/sigscan.
add_library(pemcp_sigscan INTERFACE)
target_include_directories(pemcp_sigscan SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# ---------------------------------------------------------------------------
# Warnings, first-party targets only
# ---------------------------------------------------------------------------

add_library(pemcp_warnings INTERFACE)
# /w44062: a switch over an enum that misses an enumerator is an error.
target_compile_options(pemcp_warnings INTERFACE /W4 /w44062 /permissive- /Zc:__cplusplus /utf-8)
if(PEMCP_WARNINGS_AS_ERRORS)
    target_compile_options(pemcp_warnings INTERFACE /WX)
endif()

# ---------------------------------------------------------------------------
# pemcp_core: the PE reader, the analyses, the tools and the JSON-RPC layer.
# Nothing here touches stdin or stdout, so the tests drive all of it directly.
# ---------------------------------------------------------------------------

add_library(pemcp_core STATIC
    src/pe/Bytes.h
    src/pe/Disasm.cpp
    src/pe/Disasm.h
    src/pe/Hash.cpp
    src/pe/Hash.h
    src/pe/PeFile.cpp
    src/pe/PeFile.h
    src/pe/Strings.cpp
    src/pe/Strings.h
    src/mcp/Protocol.cpp
    src/mcp/Protocol.h
    src/mcp/Tools.cpp
    src/mcp/Tools.h
)
target_compile_features(pemcp_core PUBLIC cxx_std_20)
target_include_directories(pemcp_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(pemcp_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX PEMCP_VERSION="${PROJECT_VERSION}")
target_link_libraries(pemcp_core PUBLIC Zydis pemcp_json PRIVATE pemcp_sigscan pemcp_warnings)

# ---------------------------------------------------------------------------
# pe-mcp.exe: the stdio transport around the core.
# ---------------------------------------------------------------------------

add_executable(pe_mcp src/main.cpp)
set_target_properties(pe_mcp PROPERTIES OUTPUT_NAME pe-mcp)
target_link_libraries(pe_mcp PRIVATE pemcp_core pemcp_warnings)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(PEMCP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Package: the exe and the notices.
# ---------------------------------------------------------------------------

install(TARGETS pe_mcp RUNTIME DESTINATION .)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    DESTINATION .
)

set(CPACK_PACKAGE_NAME "pe-mcp")
set(CPACK_PACKAGE_VENDOR "Game Reversal Club")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
    set(CPACK_PACKAGE_FILE_NAME "pe-mcp-v${PROJECT_VERSION}-windows-x86")
else()
    set(CPACK_PACKAGE_FILE_NAME "pe-mcp-v${PROJECT_VERSION}-windows-x64")
endif()
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MCP server for static analysis of PE files")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)
