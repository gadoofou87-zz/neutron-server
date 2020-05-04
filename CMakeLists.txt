cmake_minimum_required(VERSION 3.5)

project(neutron-server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${CMAKE_CURRENT_LIST_DIR}/.CMake)

find_package(CryptoPP REQUIRED)
find_package(liboqs REQUIRED)
find_package(Qt5 REQUIRED COMPONENTS Core Network Sql)

include_directories(
    ${CRYPTOPP_INCLUDE_DIRS}
    ${LIBOQS_INCLUDE_DIRS})

link_libraries(
    ${CRYPTOPP_LIBRARIES}
    ${LIBOQS_LIBRARIES}
    Qt5::Core
    Qt5::Network
    Qt5::Sql)

add_executable(neutron-server
    src/main.cpp
    src/client.cpp
    src/database.cpp
    src/file.cpp
    src/packet.cpp
    src/server.cpp
    src/thread.cpp)
