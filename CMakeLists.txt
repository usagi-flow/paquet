cmake_minimum_required (VERSION 3.6)
project (wintest)

# GNU: --masm=intel
# Clang: [-S] -mllvm --x86-asm-syntax=intel
set(CMAKE_CXX_FLAGS "-g -std=c++14 ${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")

#add_library(Psapi main.cpp)
add_executable(wintest main.cpp
	supervisor/process.cpp
	supervisor/runtime-exception.cpp
	supervisor/util.cpp)
target_link_libraries(wintest Psapi)

add_executable(child child/child.cpp)