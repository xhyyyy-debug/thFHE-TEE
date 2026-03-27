add_library(host_dkg STATIC
    encryption.cpp
    keygen.cpp
    params.cpp
    planner.cpp
    preprocessing_store.cpp
    serialization.cpp
)

target_include_directories(host_dkg
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

target_sources(host_dkg
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/keygen.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/encryption.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/params.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/planner.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/preprocessing_store.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/serialization.hpp
)

target_link_libraries(host_dkg
    PUBLIC
        host_config
)
