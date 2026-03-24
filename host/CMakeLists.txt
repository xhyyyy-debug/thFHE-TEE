set(PARTY_TARGET noise_party)
set(CONTROLLER_TARGET noise_ctl)
set(EDL_FILE ${CMAKE_SOURCE_DIR}/noise.edl)
set(HOST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated_proto)
set(PROTO_DIR ${CMAKE_SOURCE_DIR}/proto)
set(PROTO_FILE ${PROTO_DIR}/noise.proto)

find_package(OpenEnclave CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(absl CONFIG REQUIRED)
find_package(utf8_range CONFIG REQUIRED)

message(STATUS "Protobuf_VERSION = ${Protobuf_VERSION}")
message(STATUS "Protobuf_INCLUDE_DIRS = ${Protobuf_INCLUDE_DIRS}")
message(STATUS "gRPC_DIR = ${gRPC_DIR}")

if (TARGET protobuf::protoc)
    set(PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
else()
    set(PROTOC_EXECUTABLE ${Protobuf_PROTOC_EXECUTABLE})
endif()

if (TARGET gRPC::grpc_cpp_plugin)
    set(GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
elseif (DEFINED gRPC_CPP_PLUGIN_EXECUTABLE)
    set(GRPC_CPP_PLUGIN_EXECUTABLE ${gRPC_CPP_PLUGIN_EXECUTABLE})
elseif (DEFINED GRPC_CPP_PLUGIN_EXECUTABLE)
    set(GRPC_CPP_PLUGIN_EXECUTABLE ${GRPC_CPP_PLUGIN_EXECUTABLE})
else()
    message(FATAL_ERROR "gRPC C++ plugin executable not found")
endif()

if (TARGET openenclave::oeedger8r)
    set(OEEDGER8R_COMMAND $<TARGET_FILE:openenclave::oeedger8r>)
else()
    set(OEEDGER8R_COMMAND oeedger8r)
endif()

set(OEEDGER8R_SEARCH_ARGS --search-path ${CMAKE_SOURCE_DIR})

find_path(OE_SDK_INCLUDE_DIR
    NAMES openenclave/edl/syscall.edl
    PATHS
        /opt/openenclave/include
        /usr/local/include
        /usr/include
    REQUIRED)

list(APPEND OEEDGER8R_SEARCH_ARGS
    --search-path ${OE_SDK_INCLUDE_DIR}
)

if (EXISTS "${OE_SDK_INCLUDE_DIR}/openenclave/edl/sgx")
    list(APPEND OEEDGER8R_SEARCH_ARGS
        --search-path ${OE_SDK_INCLUDE_DIR}/openenclave/edl/sgx
    )
else()
    message(FATAL_ERROR "Open Enclave SGX EDL directory not found: ${OE_SDK_INCLUDE_DIR}/openenclave/edl/sgx")
endif()

file(MAKE_DIRECTORY ${HOST_GEN_DIR})
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

add_custom_command(
    OUTPUT
        ${HOST_GEN_DIR}/noise_u.c
        ${HOST_GEN_DIR}/noise_u.h
    COMMAND
        ${OEEDGER8R_COMMAND}
        --untrusted ${EDL_FILE}
        --untrusted-dir ${HOST_GEN_DIR}
        ${OEEDGER8R_SEARCH_ARGS}
    DEPENDS
        ${EDL_FILE}
    COMMENT "Generating Open Enclave untrusted edge routines"
)

add_custom_command(
    OUTPUT
        ${PROTO_GEN_DIR}/noise.pb.cc
        ${PROTO_GEN_DIR}/noise.pb.h
        ${PROTO_GEN_DIR}/noise.grpc.pb.cc
        ${PROTO_GEN_DIR}/noise.grpc.pb.h
    COMMAND
        ${PROTOC_EXECUTABLE}
        --grpc_out ${PROTO_GEN_DIR}
        --cpp_out ${PROTO_GEN_DIR}
        -I ${PROTO_DIR}
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
        ${PROTO_FILE}
    DEPENDS
        ${PROTO_FILE}
    COMMENT "Generating gRPC sources from noise.proto"
)

add_library(noise_grpc SHARED
    ${PROTO_GEN_DIR}/noise.pb.cc
    ${PROTO_GEN_DIR}/noise.grpc.pb.cc
)

target_include_directories(noise_grpc
    PUBLIC
        ${PROTO_GEN_DIR}
)

target_link_libraries(noise_grpc
    PUBLIC
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        absl::base
        absl::strings
        absl::log
)

add_library(host_common STATIC
    config.cpp
)

target_include_directories(host_common
    PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/host
        ${CMAKE_SOURCE_DIR}/enclave
        ${CMAKE_SOURCE_DIR}/algebra
        ${PROTO_GEN_DIR}
)

add_executable(${PARTY_TARGET}
    host.cpp
    ${HOST_GEN_DIR}/noise_u.c
)

target_include_directories(${PARTY_TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/host
        ${CMAKE_SOURCE_DIR}/enclave
        ${CMAKE_SOURCE_DIR}/algebra
        ${HOST_GEN_DIR}
)

target_link_libraries(${PARTY_TARGET}
    PRIVATE
        host_common
        noise_grpc
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        openenclave::oehost
        Threads::Threads
)

add_dependencies(${PARTY_TARGET} noise_enclave_sign)

if (NOT DEFINED NOISE_SIGNED_ENCLAVE)
    message(FATAL_ERROR "NOISE_SIGNED_ENCLAVE not set. Ensure enclave is configured before host.")
endif()

add_custom_command(
    TARGET ${PARTY_TARGET}
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different
        ${NOISE_SIGNED_ENCLAVE}
        $<TARGET_FILE_DIR:${PARTY_TARGET}>
    COMMENT "Copying signed enclave next to host binary"
)

add_executable(${CONTROLLER_TARGET}
    controller.cpp
)

target_include_directories(${CONTROLLER_TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/host
        ${CMAKE_SOURCE_DIR}/enclave
        ${CMAKE_SOURCE_DIR}/algebra
)

target_link_libraries(${CONTROLLER_TARGET}
    PRIVATE
        host_common
        noise_grpc
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)