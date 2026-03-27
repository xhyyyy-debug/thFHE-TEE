add_library(enclave_protocol INTERFACE)

target_include_directories(enclave_protocol
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(enclave_protocol
    INTERFACE
        enclave_common
        enclave_prss
        enclave_mpc
        algebra_sharing
)
