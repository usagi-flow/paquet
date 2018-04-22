#include "library.h"

using namespace std;

HMODULE ownHModule;
MODULEINFO ownModuleInfo;

static HANDLE(WINAPI * baseCreateFileA)(
	LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
static HANDLE(WINAPI * baseCreateFileW)(
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	//printf("[library] Resuming execution in 2s...\n");
	//this_thread::sleep_for(milliseconds(2000));
	//Sleep(2000);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		onDLLAttached();
		break;
	case DLL_PROCESS_DETACH:
		onDLLDetached();
		break;
	case DLL_THREAD_ATTACH:
		//printf("[library] * DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		//printf("[library] * DLL_THREAD_DETACH\n");
		break;
	default:
		printf("[library] DllMain invoked, reason unknown\n");
		break;
	}

	/*ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
	printf("[library] Time: %d\n", ms);*/

	return true;
}

void onDLLAttached()
{
	bool success;

	printf("[library] DLL_PROCESS_ATTACH\n");

	ownHModule = GetModuleHandle("paquet.dll");

	//printf("[library] Module handle:        0x%08x\n", ownHModule);

	success = GetModuleInformation(GetCurrentProcess(), ownHModule, &ownModuleInfo, sizeof(ownModuleInfo));

	if (!success)
	{
		printf("[library] - Failed to retrieve the module info\n");
		return;
	}

	createInterceptions();

	/*printf("[library] Module base:          0x%08x\n", ownModuleInfo.lpBaseOfDll);
	printf("[library] Module entry point:   0x%08x\n", ownModuleInfo.EntryPoint);
	printf("[library] Module size:          0x%08x\n", ownModuleInfo.SizeOfImage);*/
}

void onDLLDetached()
{
	printf("[library] DLL_PROCESS_DETACH\n");
}

void createInterceptions()
{
	long error;

	if (DetourIsHelperProcess())
	{
		cout << "[library] The process is a helper process" << endl;
		return;
	}

	cout << "[library] Creating interceptions" << endl;

	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)baseCreateFileA, interceptedCreateFileA);
	DetourAttach(&(PVOID&)baseCreateFileW, interceptedCreateFileW);
	error = DetourTransactionCommit();

	if (error == NO_ERROR)
	{
		//MessageBox(0x0, "paquet.dll installed successfully.", "[Interception] DLL_PROCESS_ATTACH", MB_OK);
		cout << "[library] Interception successful" << endl;
	}
	else
	{
		//MessageBox(0x0, "paquet.dll installed with errors.", "[Interception] DLL_PROCESS_ATTACH", MB_OK);
		cerr << "[library] Interception failed" << endl;
	}
}

HANDLE interceptedCreateFileA(
	LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	cout << "[library] File creation (CreateFileA) intercepted: " << lpFileName << endl;

	return interceptedCreateFileW(StringUtilities::toWString(lpFileName)->c_str(), dwDesiredAccess, dwShareMode,
		lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile);
}

HANDLE interceptedCreateFileW(
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	cout << "[library] File creation (CreateFileW) intercepted: " << *toString(lpFileName) << endl;

	if (StringUtilities::endsWith(lpFileName, L"file.txt"))
	{
		MessageBoxW(0x0, lpFileName, L"[Interception] CreateFileW", MB_OK);
	}

	return baseCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
		lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile);
}

shared_ptr<CONTEXT> getContext()
{
	shared_ptr<CONTEXT> context = make_shared<CONTEXT>();
	memset(context.get(), 0x0, sizeof(CONTEXT));

	RtlCaptureContext(context.get());

	return context;
}

/*
A simplified wchart_t* to std::string implementation which truncates each second byte and therefore
assumes that the source string is a wchar-encoded ascii string.
*/
shared_ptr<string> toString(const wchar_t * wCString)
{
	const size_t MAX_SIZE = 4096;
	const char * pCString = (const char *)wCString;
	char * result;
	size_t size;

	// Retrieve the end of the wchar string
	for (size_t i = 0; i < MAX_SIZE; ++i)
	{
		if (!*pCString)
			break;

		// Increment the wchar string pointer
		pCString = (const char *)((size_t)pCString + sizeof(wchar_t));
	}

	size = (size_t)pCString - (size_t)wCString;
	result = new char[size / sizeof(wchar_t) + 1];
	pCString = (const char *)wCString;

	// Copy the source string by taking over the first byte of each wchar
	for (size_t i = 0; i < size / sizeof(wchar_t); ++i)
	{
		// Copy the referenced byte
		result[i] = *pCString;

		// Increment the wchar string pointer
		pCString = (const char *)((size_t)pCString + sizeof(wchar_t));
	}

	// Null-terminate the C-string
	result[size / sizeof(wchar_t)] = 0x0;

	// Instanciate an std::string and return a shared pointer
	return make_shared<string>(result);
}

/*
Converts a C-string to a wchar_t string and returns a pointer to that string.
Not implemented.
*/
const wchar_t * toWCString(const string & string)
{
	return 0x0;
}

shared_ptr<string> cleansePathString(shared_ptr<string> path)
{
	const string prefix = "\\??\\";

	if (StringUtilities::startsWith(*path, prefix))
		return make_shared<string>(path->substr(prefix.size(), path->size() - prefix.size()));
	else
		return path;
}

void onNtCreateFile()
{
	return;
	shared_ptr<CONTEXT> context;
	void * possibleStr;
	void * retrievedStr;
	shared_ptr<string> path;

	cout << "[library] File creation intercepted" << endl;

	context = getContext();
	//cout << "[library] RSP: " << COUT_HEX_32 << context->Rsp << endl;
	//cout << "[library] R15: " << COUT_HEX_32 << context->R15 << endl;

	possibleStr = (char*)context->R15;
	retrievedStr = 0x0;
	//cout << "[library] Possible string pointer: " << COUT_HEX_32 << possibleStr << endl;

	const size_t initialOffset = 0xE0;
	size_t offset;
	for (size_t i = 0; i < (512 / 8); ++i)
	{
		offset = initialOffset + i * 8;
		retrievedStr = (char*)(*(size_t*)(context->Rsp + offset));

		if ((size_t)retrievedStr == (size_t)possibleStr)
			break;
	}

	/*cout << "[library] -> RSP + 0x" << COUT_HEX_32 << offset << ": 0x" <<
		retrievedStr << endl;*/

	if (!retrievedStr)
	{
		cerr << "[library] Could not determine the file path" << endl;
		return;
	}

	path = cleansePathString(toString((wchar_t*)retrievedStr));

	cout << "[library] Create file: " << *path << endl;
	//MessageBox(0x0, path->c_str(), "[Interception] NtCreateFile", MB_OK);
}

void onNtWriteFile()
{
	//printf("[library] File write intercepted!\n");
}

void onNtClose()
{
	printf("[library] Close intercepted!\n");
}