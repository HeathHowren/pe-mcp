include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

# A real compiled program for the end-to-end tests: known strings, an export,
# known imports, a TLS callback and one function that uses a known string.
add_executable(pe_mcp_fixture fixture/fixture.cpp fixture/fixture.rc)
set_target_properties(pe_mcp_fixture PROPERTIES OUTPUT_NAME pe-mcp-fixture)
target_link_libraries(pe_mcp_fixture PRIVATE pemcp_warnings)

add_executable(pemcp_tests
    SyntheticPe.h
    SyntheticPe.cpp
    TestSupport.h
    test_disasm.cpp
    test_e2e.cpp
    test_hash.cpp
    test_malformed.cpp
    test_pe.cpp
    test_protocol.cpp
    test_strings.cpp
    test_tools.cpp
)
target_include_directories(pemcp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pemcp_tests PRIVATE pemcp_core pemcp_warnings Catch2::Catch2WithMain)
target_compile_definitions(pemcp_tests PRIVATE
    PEMCP_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/golden"
    PEMCP_SERVER_EXE="$<TARGET_FILE:pe_mcp>"
    PEMCP_FIXTURE_EXE="$<TARGET_FILE:pe_mcp_fixture>"
)
add_dependencies(pemcp_tests pe_mcp pe_mcp_fixture)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(pemcp_tests)
