# Cross-compilation for Rockchip RK3588 (aarch64, Debian/Ubuntu arm64 sysroot).
#   cmake -S . -B build-arm64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-aarch64.cmake \
#         -DCMAKE_SYSROOT=/path/to/arm64-sysroot -DCMAKE_BUILD_TYPE=Release
# The sysroot must contain the arm64 -dev packages listed in README.md. protoc runs on the host
# (set Protobuf_PROTOC_EXECUTABLE if it is not in PATH); its version must match the target libprotobuf.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CROSS_PREFIX aarch64-linux-gnu- CACHE STRING "Cross toolchain prefix")
set(CMAKE_C_COMPILER ${CROSS_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${CROSS_PREFIX}g++)

if(CMAKE_SYSROOT)
  set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})
  set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_SYSROOT})
  set(ENV{PKG_CONFIG_LIBDIR} "${CMAKE_SYSROOT}/usr/lib/aarch64-linux-gnu/pkgconfig:${CMAKE_SYSROOT}/usr/share/pkgconfig")
endif()
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm64)
