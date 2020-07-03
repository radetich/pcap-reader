cmake_minimum_required(VERSION 2.8.12)

project(pcap_reader)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt5Core)

add_executable(${PROJECT_NAME} "pcap_reader.cpp")
