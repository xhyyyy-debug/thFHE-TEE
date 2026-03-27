set_source_files_properties(
    ${HOST_GEN_DIR}/noise_u.c
    PROPERTIES GENERATED TRUE
)

add_executable(noise_party
    noise_party_main.cpp
    ${HOST_GEN_DIR}/noise_u.c
)

target_include_directories(noise_party
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${HOST_GEN_DIR}
)

target_link_libraries(noise_party
    PRIVATE
        host_protocol
        host_dkg
        noise_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        openenclave::oehost
        Threads::Threads
)

add_dependencies(noise_party noise_enclave_sign)
add_dependencies(noise_party noise_host_edge)

if (NOT DEFINED NOISE_SIGNED_ENCLAVE)
    message(FATAL_ERROR "NOISE_SIGNED_ENCLAVE not set. Ensure enclave is configured before host.")
endif()

add_custom_command(
    TARGET noise_party
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different
        ${NOISE_SIGNED_ENCLAVE}
        $<TARGET_FILE_DIR:noise_party>
    COMMENT "Copying signed enclave next to host binary"
)

add_executable(noise_ctl
    noise_ctl_main.cpp
)

target_include_directories(noise_ctl
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(noise_ctl
    PRIVATE
        host_protocol
        host_dkg
        noise_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)

add_executable(noise_preproc_plan
    noise_preproc_plan_main.cpp
)

target_include_directories(noise_preproc_plan
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(noise_preproc_plan
    PRIVATE
        host_dkg
        Threads::Threads
)

add_executable(noise_preproc
    noise_preproc_main.cpp
)

target_include_directories(noise_preproc
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(noise_preproc
    PRIVATE
        host_dkg
        host_protocol
        noise_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)

add_executable(noise_keygen
    noise_keygen_main.cpp
)

target_include_directories(noise_keygen
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(noise_keygen
    PRIVATE
        host_dkg
        host_protocol
        noise_grpc
        algebra_sharing
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc
        utf8_range::utf8_range
        utf8_range::utf8_validity
        Threads::Threads
)
