cmake_minimum_required(VERSION 3.10)
project(SoapyVITA49 CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(SoapySDR CONFIG REQUIRED)
find_package(Threads REQUIRED)

# libpcap enables the passive discovery scan, which finds streams on ports
# another process already holds and on multicast groups we have not joined.
# Without it the module falls back to binding ports directly.
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

option(ENABLE_PCAP "Use libpcap for passive stream discovery" ON)

set(VITA49_SOURCES
    src/VRT.cpp
    src/Convert.cpp
    src/Discovery.cpp
    src/Control.cpp
    src/Settings.cpp
    src/RxStream.cpp
    src/TxStream.cpp
)

add_library(vita49core STATIC ${VITA49_SOURCES})
set_property(TARGET vita49core PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(vita49core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SoapySDR_INCLUDE_DIRS}
)
target_link_libraries(vita49core PUBLIC ${SoapySDR_LIBRARIES} Threads::Threads)
target_compile_options(vita49core PRIVATE -Wall -Wextra)

if(ENABLE_PCAP AND PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    target_compile_definitions(vita49core PUBLIC HAVE_PCAP)
    target_include_directories(vita49core PUBLIC ${PCAP_INCLUDE_DIR})
    target_link_libraries(vita49core PUBLIC ${PCAP_LIBRARY})
    message(STATUS "SoapyVITA49: passive discovery enabled (libpcap)")
else()
    message(STATUS "SoapyVITA49: libpcap not found, bind scan only")
endif()

# The SoapySDR module itself.
SOAPY_SDR_MODULE_UTIL(
    TARGET vita49Support
    SOURCES src/Registration.cpp
    LIBRARIES vita49core
)

# Standalone scanner. Running the sweep here rather than during device
# enumeration keeps host device lists responsive, and this binary is the one
# worth granting capture rights to.
add_executable(vita49-scan tools/vita49-scan.cpp)
target_link_libraries(vita49-scan PRIVATE vita49core)
target_compile_options(vita49-scan PRIVATE -Wall -Wextra)
install(TARGETS vita49-scan RUNTIME DESTINATION bin)

# Loopback generator, used to exercise the receive path without hardware.
add_executable(vita49-gen tools/vita49-gen.cpp)
target_link_libraries(vita49-gen PRIVATE vita49core)
target_compile_options(vita49-gen PRIVATE -Wall -Wextra)
install(TARGETS vita49-gen RUNTIME DESTINATION bin)

# Field-level packet decoder, for characterising an unfamiliar source.
add_executable(vita49-dump tools/vita49-dump.cpp)
target_link_libraries(vita49-dump PRIVATE vita49core)
target_compile_options(vita49-dump PRIVATE -Wall -Wextra)
install(TARGETS vita49-dump RUNTIME DESTINATION bin)

# Throughput benchmark: streams and discards, so only the network, the kernel
# and this module are exercised.
add_executable(vita49-bench tools/vita49-bench.cpp)
target_link_libraries(vita49-bench PRIVATE vita49core)
target_compile_options(vita49-bench PRIVATE -Wall -Wextra)
install(TARGETS vita49-bench RUNTIME DESTINATION bin)

enable_testing()
add_executable(test-vrt tests/test_vrt.cpp)
target_link_libraries(test-vrt PRIVATE vita49core)
target_compile_options(test-vrt PRIVATE -Wall -Wextra)
add_test(NAME vrt COMMAND test-vrt)
