cmake_minimum_required(VERSION 3.9)
project(dns_over_https_client C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
#set(CMAKE_C_FLAGS -flto -ffat-lto-objects -fvisibility=hidden)

#find_package(OpenSSL 1.0.2 REQUIRED)
#find_package(NGHTTP2 REQUIRED)

set(ENABLE_TESTING OFF)
add_subdirectory(third-party/mbedtls-2.8.0)
include_directories(third-party/mbedtls-2.8.0/include)
set(HAVE_CUNIT ON)
set(CMAKE_INSTALL_LIBDIR ${CMAKE_CURRENT_BINARY_DIR})
add_subdirectory(third-party/nghttp2-1.31.0/lib)
target_compile_definitions(nghttp2_static PUBLIC HAVE_ARPA_INET_H=1 HAVE_NETINET_IN_H=1)

target_compile_options(mbedcrypto PRIVATE )
#target_compile_options(mbedx509 PRIVATE  -flto -ffat-lto-objects -fvisibility=hidden)
#target_compile_options(mbedtls PRIVATE -flto -ffat-lto-objects -fvisibility=hidden)
#target_compile_options(nghttp2_static PRIVATE -flto -ffat-lto-objects -fvisibility=hidden)

add_executable(dns_over_https_client
        main.c
        dns.h
        client.c
        client.h
        logger.c
        logger.h http2.c http2.h tls.c tls.h request.c request.h util.c util.h stamp.c stamp.h)

target_link_libraries(dns_over_https_client mbedtls nghttp2_static)
#target_compile_options(dns_over_https_client PRIVATE -flto -ffat-lto-objects -fvisibility=hidden)
#set_property(TARGET dns_over_https_client PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
