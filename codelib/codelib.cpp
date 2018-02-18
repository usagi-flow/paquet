#include "codelib.h"

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
		printf("[library] DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		printf("[library] DLL_THREAD_DETACH\n");
		break;
	default:
		printf("[library] DllMain invoked, reason unknown\n");
		break;
	}

	return true;
}

void onDLLAttached()
{
	printf("[codelib] DLL_PROCESS_ATTACH\n");
}

void onDLLDetached()
{
	printf("[codelib] DLL_PROCESS_DETACH\n");
}

void testDLL()
{
	printf("[codelib] Test successful\n");
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