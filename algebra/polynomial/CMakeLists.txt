add_library(algebra_polynomial INTERFACE)

target_include_directories(algebra_polynomial
    INTERFACE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(algebra_polynomial
    INTERFACE
        algebra_base
)
