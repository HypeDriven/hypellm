cmake_minimum_required(VERSION 3.21)
project(HypeLLMMonitor VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

# The portable half: JSON reading, rate arithmetic, and what the monitor shows.
# It builds and tests on any host, which is how the Linux checkout covers it.
add_library(hypellm_monitor_core
    src/json.cpp
    src/model.cpp
)
target_include_directories(hypellm_monitor_core PUBLIC src)
target_compile_features(hypellm_monitor_core PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(hypellm_monitor_core PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(hypellm_monitor_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

option(HYPELLM_MONITOR_BUILD_APP "Build the native desktop application" ON)
if(HYPELLM_MONITOR_BUILD_APP AND WIN32)
    add_executable(hypellm-monitor WIN32 src/native_windows.cpp)
    target_link_libraries(hypellm-monitor PRIVATE hypellm_monitor_core
        user32 gdi32 comctl32 shell32 advapi32 dwmapi winhttp uxtheme ole32)
    target_include_directories(hypellm-monitor PRIVATE src)
    target_compile_definitions(hypellm-monitor PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(hypellm-monitor PRIVATE /W4 /permissive- /utf-8)
        target_link_options(hypellm-monitor PRIVATE
            "/MANIFEST:EMBED"
            "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/resources/hypellm-monitor.manifest"
        )
    else()
        target_compile_options(hypellm-monitor PRIVATE -Wall -Wextra -Wpedantic -Wno-missing-field-initializers -municode)
        target_link_options(hypellm-monitor PRIVATE -municode -static)
        target_sources(hypellm-monitor PRIVATE resources/hypellm-monitor.rc)
    endif()
    install(TARGETS hypellm-monitor RUNTIME DESTINATION .)
elseif(HYPELLM_MONITOR_BUILD_APP)
    message(STATUS "The HypeLLM Monitor desktop target is Windows 11 only; building the portable core tests on this host.")
endif()

if(BUILD_TESTING)
    add_executable(hypellm_monitor_tests tests/test_core.cpp)
    target_link_libraries(hypellm_monitor_tests PRIVATE hypellm_monitor_core)
    add_test(NAME hypellm_monitor_core_tests COMMAND hypellm_monitor_tests)
endif()
