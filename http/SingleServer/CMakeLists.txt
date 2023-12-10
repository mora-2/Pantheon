cmake_minimum_required(VERSION 3.10)

project(main VERSION 1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(main main.cpp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

target_include_directories(main PUBLIC ${CMAKE_SOURCE_DIR}/../pir)
add_subdirectory(${CMAKE_SOURCE_DIR}/../pir pir)
target_link_libraries(main PUBLIC Pantheon)