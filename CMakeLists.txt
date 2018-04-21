cmake_minimum_required (VERSION 3.6)
project (wintest)

# GNU: --masm=intel
# Clang: [-S] -mllvm --x86-asm-syntax=intel
#set(CMAKE_CXX_FLAGS "-g -std=c++14 ${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
set(CMAKE_CXX_FLAGS "-g -std=c++14 ${CMAKE_CXX_FLAGS}")

add_executable(wintest main.cpp
	supervisor/interceptor.cpp
	supervisor/injector.cpp
	supervisor/process.cpp
	supervisor/dll.cpp
	supervisor/codecave.cpp
	supervisor/assembler.cpp
	supervisor/util.cpp
	shared/runtime-exception.cpp)
target_link_libraries(wintest Psapi)

add_executable(child child/child.cpp)

add_library(paquet SHARED library/library.cpp
	shared/runtime-exception.cpp

	detours/detours.cpp
	detours/modules.cpp
	detours/disasm.cpp
	detours/image.cpp
	detours/creatwth.cpp
	detours/disolx86.cpp
	detours/disolx64.cpp
	detours/disolia64.cpp
	detours/disolarm.cpp
	detours/disolarm64.cpp)
target_link_libraries(paquet Psapi)

add_library(codelib SHARED codelib/codelib.cpp)