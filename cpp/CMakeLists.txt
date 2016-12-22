INCLUDE(FindPkgConfig)
cmake_minimum_required(VERSION 3.2)
project (RSATEST)

set(CMAKE_CXX_STANDARD 11)

pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)
include_directories(${CRYPTOPP_INCLUDE_DIRS})

file(GLOB SOURCES "src/*.cpp")

add_executable(mkcert ${SOURCES})
target_link_libraries(mkcert ${CRYPTOPP_LIBRARIES})