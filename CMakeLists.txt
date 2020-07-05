cmake_minimum_required(VERSION 2.8.3)

project(pcap_reader)
find_package(Boost COMPONENTS system filesystem)
configure_file(pcap_config.h.in pcap_config.h)

add_compile_options(-std=c++11)
set(CMAKE_CXX_FLAGS "-g -std=c++11 ${CMAKE_CXX_FLAGS}")


add_executable(pcap_reader "pcap_reader.cpp")
target_link_libraries(pcap_reader Boost::system Boost::filesystem pcap)