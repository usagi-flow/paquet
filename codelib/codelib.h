#ifndef _CODELIB_H_
#define _CODELIB_H_

#define CODELIB_NAME "codelib.dll"

#include <cstdio>
#include <windows.h>
#include <psapi.h>

#define API extern "C" __declspec(dllexport)

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

void onDLLAttached();
void onDLLDetached();

API void testDLL();

struct InjectDLLContext
{
	HMODULE (*pLoadLibraryA)(LPCSTR lpFileName);
	const char dllName[64];
};

API void injectDLL(InjectDLLContext * context);

struct InspectDLLContext
{
	// In, mandatory

	const char * dllName;

	bool(*pGetModuleHandleEx)(DWORD dwFlags, LPCSTR lpModuleName, HMODULE * phModule);
	bool(*pGetModuleInformation)(HMODULE hModule, LPCSTR lpProcName);

	// Out

	void * moduleBaseAddress;
	HMODULE hModule;
};

API void inspectDLL(InspectDLLContext * context);

struct InspectStealthDLLContext
{
	void * moduleBaseAddress;
	HMODULE hModule;
	bool(*pGetModuleHandleEx)(DWORD dwFlags, LPCSTR lpModuleName, HMODULE * phModule);
	FARPROC(*pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	bool(*pGetModuleInformation)(HMODULE hModule, LPCSTR lpProcName);
};

API void inspectStealthDLL(InspectStealthDLLContext * context);

#endif