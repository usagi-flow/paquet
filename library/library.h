#ifndef _LIBRARY_H_
#define _LIBRARY_H_

#include <cstdio>
#include <windows.h>

#define API __declspec(dllexport)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

API void test();
API void test2();

#endif