cmake_minimum_required(VERSION 3.13)
project(noise_sgx LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(enclave)
add_subdirectory(host)
