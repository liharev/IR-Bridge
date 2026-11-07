cmake_minimum_required(VERSION 3.16)
project(camai-irbridge VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(IRBRIDGE_BUILD_TESTS "Build unit tests" ON)
option(IRBRIDGE_BUILD_FUZZ "Build libFuzzer targets (clang only)" OFF)
option(IRBRIDGE_SANITIZE "Build with AddressSanitizer and UBSan" OFF)
option(IRBRIDGE_WITH_MQTT "Build MQTT publisher (libmosquitto)" ON)
option(IRBRIDGE_WITH_SYSTEMD "Use libsystemd for sd_notify" ON)
option(IRBRIDGE_WERROR "Treat warnings as errors" ON)

set(IRBRIDGE_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wcast-align -Wunused
                      -Woverloaded-virtual -Wformat=2)
if(IRBRIDGE_WERROR)
  list(APPEND IRBRIDGE_WARNINGS -Werror)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  add_compile_options(-march=armv8.2-a)
endif()

if(IRBRIDGE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(yaml-cpp REQUIRED)
find_package(nlohmann_json 3.9 REQUIRED)
find_package(spdlog REQUIRED)
find_package(PkgConfig REQUIRED)

# cpp-httplib: prefer the CMake package; otherwise the system header, plus the compiled library
# when the distribution ships httplib in split mode (Debian/Ubuntu libcpp-httplib-dev).
find_package(httplib QUIET)
if(NOT TARGET httplib::httplib)
  find_path(HTTPLIB_INCLUDE_DIR httplib.h REQUIRED)
  add_library(httplib::httplib INTERFACE IMPORTED)
  set_target_properties(httplib::httplib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${HTTPLIB_INCLUDE_DIR}")
  find_library(HTTPLIB_LIBRARY NAMES cpp-httplib)
  if(HTTPLIB_LIBRARY)
    set_target_properties(httplib::httplib PROPERTIES INTERFACE_LINK_LIBRARIES "${HTTPLIB_LIBRARY}")
  endif()
endif()

if(IRBRIDGE_WITH_MQTT)
  pkg_check_modules(MOSQUITTO REQUIRED IMPORTED_TARGET libmosquitto)
endif()
if(IRBRIDGE_WITH_SYSTEMD)
  pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
endif()

include(cmake/IntelliReaderProto.cmake)

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
file(GLOB_RECURSE IRBRIDGE_CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
if(NOT IRBRIDGE_WITH_MQTT)
  list(FILTER IRBRIDGE_CORE_SOURCES EXCLUDE REGEX ".*/pub/mqtt_mosquitto\\.cpp$")
endif()

add_library(irbridge_core STATIC ${IRBRIDGE_CORE_SOURCES})
target_include_directories(irbridge_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(irbridge_core PRIVATE ${IRBRIDGE_WARNINGS})
target_compile_definitions(irbridge_core PUBLIC IRBRIDGE_VERSION="${PROJECT_VERSION}")
target_link_libraries(irbridge_core
  PUBLIC irbridge_proto Threads::Threads SQLite::SQLite3 OpenSSL::Crypto yaml-cpp::yaml-cpp
         nlohmann_json::nlohmann_json spdlog::spdlog httplib::httplib)
if(IRBRIDGE_WITH_MQTT)
  target_link_libraries(irbridge_core PUBLIC PkgConfig::MOSQUITTO)
  target_compile_definitions(irbridge_core PUBLIC IRBRIDGE_WITH_MQTT=1)
endif()
if(IRBRIDGE_WITH_SYSTEMD)
  target_link_libraries(irbridge_core PUBLIC PkgConfig::SYSTEMD)
  target_compile_definitions(irbridge_core PUBLIC IRBRIDGE_WITH_SYSTEMD=1)
endif()

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
add_executable(irbridged apps/irbridged/main.cpp)
target_compile_options(irbridged PRIVATE ${IRBRIDGE_WARNINGS})
target_link_libraries(irbridged PRIVATE irbridge_core)

add_executable(irbridge-pcaptool apps/irbridge-pcaptool/main.cpp)
target_compile_options(irbridge-pcaptool PRIVATE ${IRBRIDGE_WARNINGS})
target_link_libraries(irbridge-pcaptool PRIVATE irbridge_core)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(IRBRIDGE_BUILD_TESTS)
  enable_testing()
  find_package(GTest REQUIRED)
  file(GLOB IRBRIDGE_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/*.cpp)
  add_executable(irbridge_tests ${IRBRIDGE_TEST_SOURCES})
  target_compile_options(irbridge_tests PRIVATE ${IRBRIDGE_WARNINGS})
  target_compile_definitions(irbridge_tests PRIVATE
    IRBRIDGE_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
  target_link_libraries(irbridge_tests PRIVATE irbridge_core GTest::gtest GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(irbridge_tests DISCOVERY_TIMEOUT 60)

  add_executable(pan_scan tests/tools/pan_scan.cpp)
  target_compile_options(pan_scan PRIVATE ${IRBRIDGE_WARNINGS})
  target_link_libraries(pan_scan PRIVATE irbridge_core)

  # Scenario regression: synth -> replay -> compare with the golden output.
  file(GLOB IRBRIDGE_SCENARIOS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/scenarios/*.yaml)
  foreach(scn ${IRBRIDGE_SCENARIOS})
    get_filename_component(scn_name ${scn} NAME_WE)
    if(scn_name MATCHES "^load_")
      continue()
    endif()
    add_test(NAME scenario_${scn_name}
      COMMAND ${CMAKE_COMMAND}
        -DPCAPTOOL=$<TARGET_FILE:irbridge-pcaptool>
        -DSCENARIO=${scn}
        -DCONFIG=${CMAKE_CURRENT_SOURCE_DIR}/tests/data/scenario-config.yaml
        -DEXPECTED=${CMAKE_CURRENT_SOURCE_DIR}/tests/data/expected/${scn_name}.jsonl
        -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/scenario_out
        -DPANSCAN=$<TARGET_FILE:pan_scan>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/RunScenario.cmake)
  endforeach()
endif()

if(IRBRIDGE_BUILD_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "IRBRIDGE_BUILD_FUZZ requires clang")
  endif()
  foreach(fz fuzz_codec fuzz_tcp fuzz_proto)
    add_executable(${fz} tests/fuzz/${fz}.cpp)
    target_compile_options(${fz} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${fz} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(${fz} PRIVATE irbridge_core)
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Install and packaging
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS irbridged irbridge-pcaptool RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES packaging/camai-irbridge.service DESTINATION lib/systemd/system)
install(FILES packaging/irbridge.yaml DESTINATION /etc/camai)
install(DIRECTORY packaging/networkd-bridge-example DESTINATION ${CMAKE_INSTALL_DATADIR}/camai-irbridge)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_NAME camai-irbridge)
set(CPACK_PACKAGE_VENDOR "AB Technology LLC")
set(CPACK_PACKAGE_CONTACT "AB Technology LLC")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "CAMAI IR-Bridge: passive monitoring of IntelliReader fare validations")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_SECTION net)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "adduser")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/postinst
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/prerm
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/conffiles)
include(CPack)
