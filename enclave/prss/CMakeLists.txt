add_library(enclave_prss INTERFACE)

target_include_directories(enclave_prss
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(enclave_prss
    INTERFACE
        enclave_common
        openenclave::oecrypto${OE_CRYPTO_LIB}
)
