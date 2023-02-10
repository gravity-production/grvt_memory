cmake_minimum_required(VERSION 3.24)
project(process)

set(CMAKE_CXX_STANDARD 17)

set(Directories
        )

Set(Sources
        process.hpp process.cpp)

add_library(process STATIC ${Sources})
target_include_directories(process PRIVATE ${Directories})
