#ifndef _LIBRARY_H_
#define _LIBRARY_H_

#include <iostream>
#include <iomanip>
#include <memory>
#include <thread>
#include <string>
#include <cstdio>
#include <windows.h>
#include <psapi.h>
#include "../shared/runtime-exception.h"
#include "../shared/macros.h"

#define API extern "C" __declspec(dllexport)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

void onDLLAttached();
void onDLLDetached();

std::shared_ptr<CONTEXT> getContext();

std::shared_ptr<std::string> toString(const wchar_t * wCString);
const wchar_t * toWCString(const std::string & string);

API void onNtCreateFile();
API void onNtWriteFile();
API void onNtClose();

#endif