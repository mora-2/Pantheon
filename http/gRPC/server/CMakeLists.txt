# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.5.1)

set(_target server)

project(${_target} C CXX)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

include(../protos/common.cmake)

# Proto file
get_filename_component(pir_proto "../protos/pantheon_pir.proto" ABSOLUTE)
get_filename_component(pir_proto_path "${pir_proto}" PATH)

# Generated sources
set(pir_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/pantheon_pir.pb.cc")
set(pir_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pantheon_pir.pb.h")
set(pir_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/pantheon_pir.grpc.pb.cc")
set(pir_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pantheon_pir.grpc.pb.h")
add_custom_command(
      OUTPUT "${pir_proto_srcs}" "${pir_proto_hdrs}" "${pir_grpc_srcs}" "${pir_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${pir_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${pir_proto}"
      DEPENDS "${pir_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# pir_grpc_proto
add_library(pir_grpc_proto
  ${pir_grpc_srcs}
  ${pir_grpc_hdrs}
  ${pir_proto_srcs}
  ${pir_proto_hdrs})
target_link_libraries(pir_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

include_directories("/home/yuance/Work/Encryption/PIR/code/PIR/Pantheon/pir")
add_subdirectory(/home/yuance/Work/Encryption/PIR/code/PIR/Pantheon/pir Pantheon)

add_executable(${_target} ${_target}.cpp)
target_link_libraries(${_target}
    pir_grpc_proto
    Pantheon
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})


