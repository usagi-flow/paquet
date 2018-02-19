#ifndef _LIBRARY_H_
#define _LIBRARY_H_

#include <chrono>
#include <thread>
#include <cstdio>
#include <windows.h>
#include <psapi.h>

#define API extern "C" __declspec(dllexport)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

void onDLLAttached();
void onDLLDetached();

API void onNtCreateFile();
API void onNtWriteFile();
API void onNtClose();

#endif