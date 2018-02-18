#ifndef _LIBRARY_H_
#define _LIBRARY_H_

#include <chrono>
#include <thread>
#include <cstdio>
#include <windows.h>
#include <psapi.h>

#define API __declspec(dllexport)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

void onDLLAttached();

API void onNtCreateFile();
API void test();
API void test2();

#endif