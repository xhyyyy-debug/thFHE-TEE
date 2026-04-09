set_source_files_properties(
    ${HOST_GEN_DIR}/dkg_u.c
    PROPERTIES GENERATED TRUE
)

add_executable(party_node
    party_node_main.cpp
    ${HOST_GEN_DIR}/dkg_u.c
)

target_include_directories(party_node
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${HOST_GEN_DIR}
)

target_link_libraries(party_node
    PRIVATE
        host_protocol
        host_dkg
        dkg_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        openenclave::oehost
        Threads::Threads
)

add_dependencies(party_node dkg_enclave_sign)
add_dependencies(party_node dkg_host_edge)

if (NOT DEFINED SIGNED_ENCLAVE_PATH)
    message(FATAL_ERROR "SIGNED_ENCLAVE_PATH not set. Ensure enclave is configured before host.")
endif()

add_custom_command(
    TARGET party_node
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different
        ${SIGNED_ENCLAVE_PATH}
        $<TARGET_FILE_DIR:party_node>
    COMMENT "Copying signed enclave next to host binary"
)

add_executable(round_controller
    round_controller_main.cpp
)

target_include_directories(round_controller
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(round_controller
    PRIVATE
        host_protocol
        host_dkg
        dkg_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)

add_executable(preprocessing_plan
    preprocessing_plan_main.cpp
)

target_include_directories(preprocessing_plan
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(preprocessing_plan
    PRIVATE
        host_dkg
        Threads::Threads
)

add_executable(preprocessing_controller
    preprocessing_controller_main.cpp
)

target_include_directories(preprocessing_controller
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(preprocessing_controller
    PRIVATE
        host_dkg
        host_protocol
        dkg_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)

add_executable(keygen_controller
    keygen_controller_main.cpp
)

target_include_directories(keygen_controller
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(keygen_controller
    PRIVATE
        host_dkg
        host_protocol
        dkg_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)

