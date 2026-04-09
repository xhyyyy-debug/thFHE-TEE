set(EDL_FILE ${CMAKE_SOURCE_DIR}/dkg.edl)
set(HOST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated_proto)
set(PROTO_DIR ${CMAKE_SOURCE_DIR}/proto)
set(PROTO_FILE ${PROTO_DIR}/dkg.proto)

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
        ${HOST_GEN_DIR}/dkg_u.c
        ${HOST_GEN_DIR}/dkg_u.h
    COMMAND
        ${OEEDGER8R_COMMAND}
        --untrusted ${EDL_FILE}
        --untrusted-dir ${HOST_GEN_DIR}
        ${OEEDGER8R_SEARCH_ARGS}
    DEPENDS
        ${EDL_FILE}
    COMMENT "Generating Open Enclave untrusted edge routines"
)

set_source_files_properties(
    ${HOST_GEN_DIR}/dkg_u.c
    ${HOST_GEN_DIR}/dkg_u.h
    PROPERTIES GENERATED TRUE
)

add_custom_target(dkg_host_edge
    DEPENDS
        ${HOST_GEN_DIR}/dkg_u.c
        ${HOST_GEN_DIR}/dkg_u.h
)

add_custom_command(
    OUTPUT
        ${PROTO_GEN_DIR}/dkg.pb.cc
        ${PROTO_GEN_DIR}/dkg.pb.h
        ${PROTO_GEN_DIR}/dkg.grpc.pb.cc
        ${PROTO_GEN_DIR}/dkg.grpc.pb.h
    COMMAND
        ${PROTOC_EXECUTABLE}
        --grpc_out ${PROTO_GEN_DIR}
        --cpp_out ${PROTO_GEN_DIR}
        -I ${PROTO_DIR}
        --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
        ${PROTO_FILE}
    DEPENDS
        ${PROTO_FILE}
    COMMENT "Generating gRPC sources from dkg.proto"
)

add_library(dkg_grpc SHARED
    ${PROTO_GEN_DIR}/dkg.pb.cc
    ${PROTO_GEN_DIR}/dkg.grpc.pb.cc
)

target_include_directories(dkg_grpc
    PUBLIC
        ${PROTO_GEN_DIR}
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(dkg_grpc
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

add_subdirectory(transport)
add_subdirectory(config)
add_subdirectory(protocol)
add_subdirectory(dkg)
add_subdirectory(apps)

