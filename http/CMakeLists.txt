cmake_minimum_required(VERSION 3.10)

project(main VERSION 1.0 LANGUAGES CXX)

# set(CMAKE_C_COMPILER gcc)
# set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 17)

include(CheckCXXCompilerFlag)
function(seal_enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
seal_enable_cxx_compiler_flag_if_supported("-g -O0")

add_executable(main main.cpp)

set_target_properties(main PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

target_include_directories(main PUBLIC ../pir)
add_subdirectory(../pir pir)
# target_link_directories(main PUBLIC ../pir/lib)
target_link_libraries(main PUBLIC Pantheon)

find_package(SEAL 0.0.0 EXACT REQUIRED)
find_package(OpenMP REQUIRED)
target_link_libraries(main PUBLIC SEAL::seal OpenMP::OpenMP_CXX crypto)