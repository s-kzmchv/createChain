cmake_minimum_required(VERSION 3.12)
project(createChain)

set(CMAKE_CXX_STANDARD 14)

add_executable(createChain main.cpp)
target_link_libraries(createChain Crypt32.Lib)
