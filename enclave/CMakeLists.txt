set(ENCLAVE_TARGET noise_enclave)

add_enclave(
    TARGET ${ENCLAVE_TARGET}
    UUID 1f6b8c84-8b48-4e54-9f5e-ff8cc1ce9c01
    CXX
    SOURCES
        enc.cpp
        ecalls.cpp
    EDL
        ${CMAKE_SOURCE_DIR}/noise.edl)

enclave_include_directories(
    ${ENCLAVE_TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/algebra)

enclave_compile_definitions(
    ${ENCLAVE_TARGET}
    PRIVATE
        OE_API_VERSION=2)

enclave_link_libraries(
    ${ENCLAVE_TARGET}
    oeenclave
    oelibcxx
)

add_enclave_signer(
    TARGET ${ENCLAVE_TARGET}_sign
    ENCLAVE ${ENCLAVE_TARGET}
    CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/enclave.conf
    KEY ${CMAKE_CURRENT_SOURCE_DIR}/private.pem)
