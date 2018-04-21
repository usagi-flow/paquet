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
#include "../detours/detours.h"

#define API extern "C" __declspec(dllexport)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

void onDLLAttached();
void onDLLDetached();

void createInterceptions();

HANDLE interceptedCreateFileA(
	LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE interceptedCreateFileW(
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

std::shared_ptr<CONTEXT> getContext();

std::shared_ptr<std::string> toString(const wchar_t * wCString);
const wchar_t * toWCString(const std::string & string);

std::shared_ptr<std::string> cleansePathString(std::shared_ptr<std::string> path);

API void onNtCreateFile();
API void onNtWriteFile();
API void onNtClose();

#endif