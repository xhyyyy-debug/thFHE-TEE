add_library(host_dkg STATIC
    encryption.cpp
    params.cpp
    planner.cpp
    preprocessing_artifacts.cpp
    artifact_serialization.cpp
)

target_include_directories(host_dkg
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

target_sources(host_dkg
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/dkg_artifacts.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/encryption.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/params.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/planner.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/preprocessing_artifacts.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/artifact_serialization.hpp
)

target_link_libraries(host_dkg
    PUBLIC
        host_config
)
