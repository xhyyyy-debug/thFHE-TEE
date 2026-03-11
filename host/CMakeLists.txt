set(PARTY_TARGET noise_party)
set(CONTROLLER_TARGET noise_ctl)
set(EDL_FILE ${CMAKE_SOURCE_DIR}/noise.edl)
set(HOST_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

find_package(Threads REQUIRED)

if (TARGET openenclave::oeedger8r)
    set(OEEDGER8R_COMMAND $<TARGET_FILE:openenclave::oeedger8r>)
else()
    set(OEEDGER8R_COMMAND oeedger8r)
endif()

set(OEEDGER8R_SEARCH_ARGS --search-path ${CMAKE_SOURCE_DIR})

find_path(OE_SDK_INCLUDE_DIR
    NAMES openenclave/edl/syscall.edl
    PATHS
        /opt/openenclave/include
        /usr/local/include
        /usr/include
    REQUIRED)

list(APPEND OEEDGER8R_SEARCH_ARGS
    --search-path ${OE_SDK_INCLUDE_DIR}
)

if (EXISTS "${OE_SDK_INCLUDE_DIR}/openenclave/edl/sgx")
    list(APPEND OEEDGER8R_SEARCH_ARGS
        --search-path ${OE_SDK_INCLUDE_DIR}/openenclave/edl/sgx
    )
else()
    message(FATAL_ERROR "Open Enclave SGX EDL directory not found: ${OE_SDK_INCLUDE_DIR}/openenclave/edl/sgx")
endif()

file(MAKE_DIRECTORY ${HOST_GEN_DIR})

add_custom_command(
    OUTPUT
        ${HOST_GEN_DIR}/noise_u.c
        ${HOST_GEN_DIR}/noise_u.h
    COMMAND
        ${OEEDGER8R_COMMAND}
        --untrusted ${EDL_FILE}
        --untrusted-dir ${HOST_GEN_DIR}
        ${OEEDGER8R_SEARCH_ARGS}
    DEPENDS
        ${EDL_FILE}
    COMMENT "Generating Open Enclave untrusted edge routines")

add_library(
    host_common
    STATIC
        config.cpp
        network.cpp)

target_include_directories(
    host_common
    PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/host
        ${CMAKE_SOURCE_DIR}/enclave
        ${CMAKE_SOURCE_DIR}/algebra)

add_executable(
    ${PARTY_TARGET}
    host.cpp
    ${HOST_GEN_DIR}/noise_u.c)

target_include_directories(
    ${PARTY_TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/host
        ${CMAKE_SOURCE_DIR}/enclave
        ${CMAKE_SOURCE_DIR}/algebra
        ${HOST_GEN_DIR})

target_link_libraries(
    ${PARTY_TARGET}
    PRIVATE
        host_common
        openenclave::oehost
        Threads::Threads)

add_dependencies(${PARTY_TARGET} noise_enclave_sign)

if (NOT DEFINED NOISE_SIGNED_ENCLAVE)
    message(FATAL_ERROR "NOISE_SIGNED_ENCLAVE not set. Ensure enclave is configured before host.")
endif()

add_custom_command(
    TARGET ${PARTY_TARGET}
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different
        ${NOISE_SIGNED_ENCLAVE}
        $<TARGET_FILE_DIR:${PARTY_TARGET}>
    COMMENT "Copying signed enclave next to host binary")

add_executable(
    ${CONTROLLER_TARGET}
    controller.cpp)

target_include_directories(
    ${CONTROLLER_TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/host
        ${CMAKE_SOURCE_DIR}/enclave
        ${CMAKE_SOURCE_DIR}/algebra)

target_link_libraries(
    ${CONTROLLER_TARGET}
    PRIVATE
        host_common
        Threads::Threads)
