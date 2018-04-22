#include "codelib.h"

#define DEBUG 0x0

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		onDLLAttached();
		break;
	case DLL_PROCESS_DETACH:
		onDLLDetached();
		break;
	case DLL_THREAD_ATTACH:
#if DEBUG > 0
		printf("[library] DLL_THREAD_ATTACH\n");
#endif
		break;
	case DLL_THREAD_DETACH:
#if DEBUG > 0
		printf("[library] DLL_THREAD_DETACH\n");
#endif
		break;
	default:
		printf("[library] DllMain invoked, reason unknown\n");
		break;
	}

	return true;
}

void onDLLAttached()
{
#if DEBUG > 0
	printf("[codelib] DLL_PROCESS_ATTACH\n");
#endif
}

void onDLLDetached()
{
#if DEBUG > 0
	printf("[codelib] DLL_PROCESS_DETACH\n");
#endif
}

void testDLL()
{
#if DEBUG > 0
	printf("[codelib] Test successful\n");
#endif
}

void inspectDLL(InspectDLLContext * context)
{
	HANDLE hProcess = 0x0;
	HMODULE hModule = 0x0;
	MODULEINFO moduleInfo;

	memset(&moduleInfo, 0x0, sizeof(MODULEINFO));

	context->pGetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCTSTR)context->dllName, &hModule);
	hProcess = context->pGetCurrentProcess();
	context->pGetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	context->hModule = hModule;
	context->moduleBaseAddress = moduleInfo.lpBaseOfDll;
}

void inspectStealthDLL(InspectStealthDLLContext * context)
{
	HMODULE hModule = 0x0;

	context->pGetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCTSTR)context->moduleBaseAddress, &hModule);

	context->hModule = hModule;
}

void loadFunctionAddress(LoadFunctionAddressContext * context)
{
	context->functionAddress = context->pGetProcAddress(context->hModule, context->functionName);
}