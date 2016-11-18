cmake_minimum_required(VERSION 3.4)

set (CMAKE_CXX_STANDARD 11)

find_package (OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(server clarcnet.cpp server.cpp)
target_link_libraries(server ${OPENSSL_CRYPTO_LIBRARY})

add_executable(client clarcnet.cpp client.cpp)
target_link_libraries(client ${OPENSSL_CRYPTO_LIBRARY})

add_executable(tests clarcnet.cpp tests.cpp)
target_link_libraries(tests ${OPENSSL_CRYPTO_LIBRARY})
