# Generates C++ sources from the vendor IntelliReader .proto files.
#
# The vendor tree has two import roots:
#   third_party/intellireader-proto/intellireader  -> imports like "misc/leds.proto"
#   third_party/intellireader-proto                -> common/failure.proto, common/notification.proto
# The .proto files are used as delivered by Vendotek, Ltd. and must not be edited.

set(IR_PROTO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/intellireader-proto)
set(IR_PROTO_GEN ${CMAKE_CURRENT_BINARY_DIR}/proto_gen)
file(MAKE_DIRECTORY ${IR_PROTO_GEN})

file(GLOB_RECURSE IR_PROTO_FILES CONFIGURE_DEPENDS RELATIVE ${IR_PROTO_ROOT}/intellireader
     ${IR_PROTO_ROOT}/intellireader/*.proto)
file(GLOB IR_COMMON_PROTO_FILES CONFIGURE_DEPENDS RELATIVE ${IR_PROTO_ROOT} ${IR_PROTO_ROOT}/common/*.proto)

set(IR_PROTO_SRCS)
set(IR_PROTO_HDRS)
set(IR_PROTO_ABS)
foreach(rel ${IR_PROTO_FILES})
  string(REGEX REPLACE "\\.proto$" "" base ${rel})
  list(APPEND IR_PROTO_SRCS ${IR_PROTO_GEN}/${base}.pb.cc)
  list(APPEND IR_PROTO_HDRS ${IR_PROTO_GEN}/${base}.pb.h)
  list(APPEND IR_PROTO_ABS ${IR_PROTO_ROOT}/intellireader/${rel})
endforeach()
set(IR_COMMON_SRCS)
set(IR_COMMON_HDRS)
set(IR_COMMON_ABS)
foreach(rel ${IR_COMMON_PROTO_FILES})
  string(REGEX REPLACE "\\.proto$" "" base ${rel})
  list(APPEND IR_COMMON_SRCS ${IR_PROTO_GEN}/${base}.pb.cc)
  list(APPEND IR_COMMON_HDRS ${IR_PROTO_GEN}/${base}.pb.h)
  list(APPEND IR_COMMON_ABS ${IR_PROTO_ROOT}/${rel})
endforeach()

add_custom_command(
  OUTPUT ${IR_PROTO_SRCS} ${IR_PROTO_HDRS}
  COMMAND protobuf::protoc -I ${IR_PROTO_ROOT}/intellireader --cpp_out ${IR_PROTO_GEN} ${IR_PROTO_FILES}
  WORKING_DIRECTORY ${IR_PROTO_ROOT}/intellireader
  DEPENDS ${IR_PROTO_ABS} protobuf::protoc
  COMMENT "Generating C++ from IntelliReader .proto files"
  VERBATIM)

add_custom_command(
  OUTPUT ${IR_COMMON_SRCS} ${IR_COMMON_HDRS}
  COMMAND protobuf::protoc -I ${IR_PROTO_ROOT} --cpp_out ${IR_PROTO_GEN} ${IR_COMMON_PROTO_FILES}
  WORKING_DIRECTORY ${IR_PROTO_ROOT}
  DEPENDS ${IR_COMMON_ABS} protobuf::protoc
  COMMENT "Generating C++ from IntelliReader common .proto files"
  VERBATIM)

add_library(irbridge_proto STATIC ${IR_PROTO_SRCS} ${IR_COMMON_SRCS})
target_include_directories(irbridge_proto SYSTEM PUBLIC ${IR_PROTO_GEN})
target_link_libraries(irbridge_proto PUBLIC protobuf::libprotobuf)
# Generated code is not ours: never fail the build on its warnings.
target_compile_options(irbridge_proto PRIVATE -w)
