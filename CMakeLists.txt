cmake_minimum_required(VERSION 3.10)

project(mynmap CXX)

add_executable(mynmap mynmap.cpp)

include_directories(threadpool-cpp/include)

set(CMAKE_CXX_STANDARD 11)

