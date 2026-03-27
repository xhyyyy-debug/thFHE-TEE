add_library(host_protocol INTERFACE)

target_include_directories(host_protocol
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(host_protocol
    INTERFACE
        host_config
)
