add_library(algebra_sharing INTERFACE)

target_sources(algebra_sharing
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/mul.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/open.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shamir.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shamir_ring.hpp
)

target_include_directories(algebra_sharing
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(algebra_sharing
    INTERFACE
        algebra_base
        algebra_polynomial
        algebra_rings
)
