add_library(algebra_rings INTERFACE)

target_include_directories(algebra_rings
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(algebra_rings
    INTERFACE
        algebra_base
)
