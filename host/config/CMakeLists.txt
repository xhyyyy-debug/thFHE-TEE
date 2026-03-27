add_library(host_config STATIC
    config.cpp
)

target_include_directories(host_config
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(host_config
    PUBLIC
        host_transport
)
