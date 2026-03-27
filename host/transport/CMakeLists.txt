add_library(host_transport STATIC
    network.cpp
)

target_include_directories(host_transport
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)
