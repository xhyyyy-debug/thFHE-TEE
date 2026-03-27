set(ENCLAVE_TARGET noise_enclave)
set(EDL_FILE ${CMAKE_SOURCE_DIR}/noise.edl)
set(ENCLAVE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(OE_CRYPTO_LIB mbedtls)

if (TARGET openenclave::oeedger8r)
    set(OEEDGER8R_COMMAND openenclave::oeedger8r)
else()
    set(OEEDGER8R_COMMAND oeedger8r)
endif()

file(MAKE_DIRECTORY ${ENCLAVE_GEN_DIR})

add_subdirectory(common)
add_subdirectory(prss)
add_subdirectory(mpc)
add_subdirectory(protocol)

add_custom_command(
    OUTPUT
        ${ENCLAVE_GEN_DIR}/noise_t.c
        ${ENCLAVE_GEN_DIR}/noise_t.h
    COMMAND
        ${OEEDGER8R_COMMAND}
        --trusted ${EDL_FILE}
        --trusted-dir ${ENCLAVE_GEN_DIR}
        --search-path ${OE_INCLUDEDIR}
        --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    DEPENDS
        ${EDL_FILE}
    COMMENT "Generating Open Enclave trusted edge routines")

add_executable(
    ${ENCLAVE_TARGET}
    enc.cpp
    ecalls.cpp
    ${ENCLAVE_GEN_DIR}/noise_t.c)

target_include_directories(
    ${ENCLAVE_TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/algebra
        ${ENCLAVE_GEN_DIR})

target_compile_definitions(
    ${ENCLAVE_TARGET}
    PRIVATE
        OE_API_VERSION=2)

target_link_libraries(
    ${ENCLAVE_TARGET}
    PRIVATE
        enclave_protocol
        openenclave::oeenclave
        openenclave::oecrypto${OE_CRYPTO_LIB}
        openenclave::oelibc
        openenclave::oelibcxx)

if (TARGET openenclave::oesign)
    set(OESIGN_COMMAND $<TARGET_FILE:openenclave::oesign>)
else()
    find_program(OESIGN_COMMAND oesign)
endif()

if (OESIGN_COMMAND)
    set(SIGNED_ENCLAVE ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_TARGET}.signed)
    add_custom_command(
        OUTPUT ${SIGNED_ENCLAVE}
        COMMAND
            ${OESIGN_COMMAND} sign
            -e $<TARGET_FILE:${ENCLAVE_TARGET}>
            -c ${CMAKE_CURRENT_SOURCE_DIR}/enclave.conf
            -k ${CMAKE_CURRENT_SOURCE_DIR}/private.pem
            -o ${SIGNED_ENCLAVE}
        DEPENDS
            ${ENCLAVE_TARGET}
            ${CMAKE_CURRENT_SOURCE_DIR}/enclave.conf
            ${CMAKE_CURRENT_SOURCE_DIR}/private.pem
        COMMENT "Signing enclave")
    add_custom_target(${ENCLAVE_TARGET}_sign ALL DEPENDS ${SIGNED_ENCLAVE})
    set(NOISE_SIGNED_ENCLAVE ${SIGNED_ENCLAVE} CACHE FILEPATH "Path to signed enclave" FORCE)
else()
    message(FATAL_ERROR "oesign not found. Install Open Enclave SDK or add it to PATH.")
endif()
