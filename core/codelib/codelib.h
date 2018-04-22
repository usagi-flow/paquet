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

struct InspectDLLContext
{
	// In, mandatory

	const char * dllName;

	HANDLE(*pGetCurrentProcess)();
	bool(*pGetModuleHandleEx)(DWORD dwFlags, LPCSTR lpModuleName, HMODULE * phModule);
	bool(*pGetModuleInformation)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);

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

struct LoadFunctionAddressContext
{
	// In, mandatory

	HMODULE hModule;
	const char * functionName;

	FARPROC(*pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

	// Out

	void * functionAddress;
};

API void loadFunctionAddress(LoadFunctionAddressContext * context);

#endif