add_library(enclave_mpc INTERFACE)

target_include_directories(enclave_mpc
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(enclave_mpc
    INTERFACE
        enclave_common
        enclave_prss
        algebra_sharing
)
