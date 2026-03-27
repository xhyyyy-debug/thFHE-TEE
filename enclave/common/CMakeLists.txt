add_library(enclave_common INTERFACE)

target_include_directories(enclave_common
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(enclave_common
    INTERFACE
        algebra_rings
)
