cmake_minimum_required (VERSION 3.5)

project(snes-rom-corruptor)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall -Werror)
include_directories(extern/Lyra/include)
include_directories(extern/spdlog/include)

add_executable(snes-rom-corruptor main.cpp)