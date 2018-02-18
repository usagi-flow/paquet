#include "injector.h"

// Defined offsets
#define JUMP_NEAR_SIZE	0x5

#define INJECT_DLL_STEALTHED

using namespace std;

HMODULE Injector::hCodeLibModule = 0x0;

Injector::Injector(std::shared_ptr<Process> process)
{
	this->process = process;
	this->initialRIP = 0x0;
	this->ntdllBase = 0x0;
	this->kernel32Base = 0x0;
	this->offsetNtOpenFile = 0x0;
	this->offsetNtWriteFile = 0x0;
	this->offsetRtlUserThreadStart = 0x0;
	this->offsetNtCreateFile = 0x0;
	this->offsetGetCurrentProcess = 0x0;
	this->offsetGetModuleHandleExA = 0x0;
	this->offsetGetProcAddress = 0x0;
	this->offsetLoadLibraryA = 0x0;
	this->offsetK32GetModuleInformation = 0x0;
	this->dllBuffer = 0x0;
	this->dllSize = 0x0;
	this->pInspectDLL = 0x0;

	cout << "[parent] * Initialized Injector instance @ 0x" << COUT_HEX_32 << this << endl;
	cout << "[parent] * Process image name: " << this->process->getName() << endl;
}

Injector::~Injector() noexcept(false)
{
}

void Injector::prepare()
{
	this->loadCodeLib();
	this->analyzeProcess();
	this->prepareCodeCaves();
}

void Injector::performInjections()
{
	if (!this->initialRIP)
		throw RuntimeException("The injector is not prepared");

	this->inject(this->cave_RtlUserThreadStart);
	this->inject(this->cave_NtCreateFile);
}

shared_ptr<DLL> Injector::injectDLL(const string & fileName)
{
	void * fileNameAddress;
	void * loadLibraryAddress;

	cout << "[parent] - Injecting DLL: " << fileName << endl;

	// Calculate the remote LoadLibaryA() address
	loadLibraryAddress = (void*)((size_t)this->kernel32Base + this->offsetLoadLibraryA);

	// Inject the file name and ensure it is null-terminated
	fileNameAddress = this->injectString(fileName);

	// Invoke the LoadLibaryA() function remotely
	this->process->spawnThread(loadLibraryAddress, fileNameAddress);

	cout << "[parent] - Injected DLL" << endl;

	return this->inspectInjectedDLL(fileName, fileNameAddress);
}

void _injectDLL(const string & fileName)
{
	/*
#ifdef INJECT_DLL_STEALTHED
	this->injectDLLStealthed(fileName);
	return;
#endif

	byte loadLibraryCaller[64];
	size_t i = 0;

	void * loadLibraryCallerAddress;
	void * loadLibraryResultAddress;
	void * loadLibraryAddress;
	size_t fileNameSize;
	void * fileNameAddress;
	byte zeroBytes[] = {0x0, 0x0};
	HANDLE hThread;

	if (!this->initialRIP)
		throw RuntimeException("The injector is not prepared");

	cout << "[parent] - Injecting DLL: " << fileName << endl;

	loadLibraryAddress = (void*)((size_t)this->kernel32Base + this->offsetLoadLibraryA);

	// Inject the file name and ensure it is null-terminated
	fileNameSize = fileName.length();
	fileNameAddress = this->process->allocateMemory(fileNameSize + sizeof(zeroBytes));
	this->process->writeMemory(fileName.c_str(), fileNameSize, fileNameAddress);
	this->process->writeMemory(zeroBytes, sizeof(zeroBytes), (void*)((size_t)fileNameAddress + fileNameSize));

	// Inject code to load the library
	loadLibraryCallerAddress = this->process->allocateMemory(sizeof(loadLibraryCaller));
	loadLibraryResultAddress = this->process->allocateMemory(64);
	memset(loadLibraryCaller, 0x0, sizeof(loadLibraryCaller));

	Assembler::writePush(loadLibraryCaller, i++, Assembler::RAX);
	Assembler::writePush(loadLibraryCaller, i++, Assembler::RBX);
	Assembler::writePush(loadLibraryCaller, i++, Assembler::RCX);
	Assembler::writePush(loadLibraryCaller, i++, Assembler::RDX);

	loadLibraryCaller[i++] = 0x48;	// MOV
	loadLibraryCaller[i++] = 0xB8;	// RAX,
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[0]; // kernel32.LoadLibraryA
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[1];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[2];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[3];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[4];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[5];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[6];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryAddress)[7];

	loadLibraryCaller[i++] = 0x48;	// MOV
	loadLibraryCaller[i++] = 0xB9;	// RCX,
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[0]; // File name buffer
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[1];
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[2];
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[3];
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[4];
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[5];
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[6];
	loadLibraryCaller[i++] = ((byte*)&fileNameAddress)[7];

	loadLibraryCaller[i++] = 0xFF;	// CALL
	loadLibraryCaller[i++] = 0xD0;	// RAX

	loadLibraryCaller[i++] = 0x48;	// MOV
	loadLibraryCaller[i++] = 0xA3;	// [...], RAX
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[0]; // Result buffer
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[1];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[2];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[3];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[4];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[5];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[6];
	loadLibraryCaller[i++] = ((byte*)&loadLibraryResultAddress)[7];

	Assembler::writePop(loadLibraryCaller, i++, Assembler::RDX);
	Assembler::writePop(loadLibraryCaller, i++, Assembler::RCX);
	Assembler::writePop(loadLibraryCaller, i++, Assembler::RBX);
	Assembler::writePop(loadLibraryCaller, i++, Assembler::RAX);

	loadLibraryCaller[i++] = 0xC3;	// RET

	cout << "[parent]   - LoadLibraryA caller address: 0x" << COUT_HEX_32 << loadLibraryCallerAddress << endl;
	cout << "[parent]   - Result buffer address: 0x" << COUT_HEX_32 << loadLibraryResultAddress << endl;

	this->process->writeMemory(loadLibraryCaller, sizeof(loadLibraryCaller), loadLibraryCallerAddress);

	//cout << "[parent] - About to spawn the remote thread..." << endl;
	//cin.get();

	// Spawn a thread to load the library
	cout << "[parent]   - Spawning thread" << endl;
	hThread = this->process->spawnThread(loadLibraryCallerAddress, fileNameAddress);
	//hThread = this->process->spawnThread(loadLibraryAddress, fileNameAddress);

	cout << "[parent] - Injected DLL" << endl;

	//this->process->getModules();*/
}

void Injector::injectDLLStealthed(const string & fileName)
{
	//const unsigned long maxReads = 1073741824L; // Max size = 1Gb * sizeof(readBuffer) = 4096Gb
	const unsigned long maxReads = 1048576L; // Max size = 1Mb * sizeof(readBuffer) = 4Gb

	unsigned long i = 0;
	byte readBuffer[4096];
	size_t size;
	size_t allocationSize;
	ifstream dll;
	void * address;
	void * targetAddress;

	if (!this->initialRIP)
		throw RuntimeException("The injector is not prepared");

	cout << "[parent] - Injecting stealth DLL: " << fileName << endl;

	dll = ifstream(fileName, ifstream::ate | ifstream::binary);

	if (!dll.is_open())
		throw RuntimeException("Failed to open the DLL");

	size = dll.tellg();

	if (size > 0)
	{
		allocationSize = size + (sizeof(readBuffer) - (size % sizeof(readBuffer)));
		cout << "[parent]   - Buffer size: " << dec << sizeof(readBuffer) << endl;
		cout << "[parent]   - File size: " << dec << size << endl;
		cout << "[parent]   - Allocation size: " << dec << allocationSize << endl;

		address = this->process->allocateMemory(size);

		while (dll.read((char*)readBuffer, sizeof(readBuffer)))
		{
			targetAddress = (void*)((size_t)address + i * sizeof(readBuffer));
			this->process->writeMemory(readBuffer, sizeof(readBuffer), targetAddress);

			++i;

			if (i > maxReads)
			{
				cerr << "[parent]   - Maximum read count exceeded" << endl;
				break;
			}
		}
	}
	else
	{
		throw RuntimeException("No valid DLL file");
	}

	dll.close();

	cout << "[parent] - Injected DLL at 0x" << COUT_HEX_32 << address << endl;

	this->inspectInjectedDLL(address);
}

void * Injector::injectString(const string & value)
{
	void * address = this->process->allocateMemory(value.length() + 2);
	byte zeroBytes[2] = { 0x0, 0x0 };

	this->process->writeMemory(value.c_str(), value.length(), address);
	this->process->writeMemory(zeroBytes, sizeof(zeroBytes), (void*)((size_t)address + value.length()));

	return address;
}

void * Injector::executeLocalFunctionRemotely(void * function, void * context, size_t contextSize)
{
	cout << "[parent] - Invoking function in remote process" << endl;

	void * functionAddress = this->injectLocalFunction(function);
	void * contextAddress = this->process->allocateMemory(contextSize);

	cout << "[parent]   - Remote function:  0x" << COUT_HEX_32 << functionAddress << endl;
	cout << "[parent]   - Remote context:   0x" << COUT_HEX_32 << contextAddress << endl;

	this->process->writeMemory(context, contextSize, contextAddress);

	this->process->spawnThread(functionAddress, contextAddress);

	this->process->readMemory(contextAddress, context, contextSize);

	cout << "[parent] - Function invoked" << endl;

	return contextAddress;
}

void * Injector::getRemoteFunctionAddress(std::shared_ptr<DLL> dll, const std::string & functionName)
{
	LoadFunctionAddressContext context;

	cout << "[parent] - Loading remote function address for \"" << functionName << "\"" << endl;

	memset(&context, 0x0, sizeof(context));

	context.hModule = dll->getHandle();
	context.functionName = (const char *)this->injectString(functionName);
	context.pGetProcAddress = (FARPROC(*)(HMODULE, LPCSTR))
	((size_t)this->kernel32Base + this->offsetGetProcAddress);

	this->executeLocalFunctionRemotely(this->pLoadFunctionAddress,
	&context, sizeof(context));

	if (!context.functionAddress)
		throw RuntimeException("Could not load the remote function address");

	return context.functionAddress;
}

void Injector::loadCodeLib()
{
	HMODULE hModule = 0x0;
	void (*pTestDLL)() = 0x0;

	if (!Injector::hCodeLibModule)
	{
		cout << "[parent] - Loading codelib.dll" << endl;
		hModule = LoadLibrary("codelib.dll");
		Injector::hCodeLibModule = hModule;

		cout << "[parent] - CodeLib loaded, performing test" << endl;

		pTestDLL = (void(*)())GetProcAddress(hModule, "testDLL");
		if (pTestDLL != 0x0)
			pTestDLL();
		else
			throw RuntimeException("CodeLib test failed");
	}
	else
	{
		cout << "[parent] - codelib.dll is already present" << endl;
	}

	this->loadLocalSymbols();

	cout << "[parent] - CodeLib module handle: 0x" << COUT_HEX_32 << hCodeLibModule << endl;
}

void Injector::analyzeProcess()
{
	cout << "[parent] - Analyzing memory" << endl;

	this->initialRIP = (void*)this->process->getMainThreadContext()->Rip;
	this->calculateSymbolOffsets();
	this->ntdllBase = (void*)((size_t)this->initialRIP - this->offsetRtlUserThreadStart);
	//this->kernel32Base = 0x0;

	cout << "[parent] - Initial RIP:            0x" << COUT_HEX_32 << this->initialRIP << endl;
	cout << "[parent] - Calculated ntdll base:  0x" << COUT_HEX_32 << this->ntdllBase << endl;

	cout << "[parent] - ntdll.dll!NtReadFile:   0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtReadFile) << endl;
	cout << "[parent] - ntdll.dll!NtWriteFile:  0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtWriteFile) << endl;
	cout << "[parent] - ntdll.dll!NtOpenFile:   0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtOpenFile) << endl;
	cout << "[parent] - ntdll.dll!NtCreateFile: 0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtCreateFile) << endl;

	cout << "[parent] - kernel32.dll!LoadLibraryA: 0x" << COUT_HEX_32 <<
		((size_t)this->kernel32Base + this->offsetLoadLibraryA) << endl;
	cout << "[parent] - kernel32.dll!GetCurrentProcess: 0x" << COUT_HEX_32 <<
		((size_t)this->kernel32Base + this->offsetGetCurrentProcess) << endl;
	cout << "[parent] - kernel32.dll!GetModuleHandleExA: 0x" << COUT_HEX_32 <<
		((size_t)this->kernel32Base + this->offsetGetModuleHandleExA) << endl;
	cout << "[parent] - kernel32.dll!GetProcAddress: 0x" << COUT_HEX_32 <<
		((size_t)this->kernel32Base + this->offsetGetProcAddress) << endl;
	cout << "[parent] - kernel32.dll!K32GetModuleInformation: 0x" << COUT_HEX_32 <<
		((size_t)this->kernel32Base + this->offsetK32GetModuleInformation) << endl;
}

void Injector::calculateSymbolOffsets()
{
	HMODULE ntdllModuleHandle = GetModuleHandle("ntdll.dll");
	HMODULE kernel32ModuleHandle = GetModuleHandle("kernel32.dll");

	MODULEINFO ntdllModuleInfo;
	MODULEINFO kernel32ModuleInfo;

	if (!ntdllModuleHandle)
	{
		cerr << "[parent] - Could not retrieve own ntdll.dll module" << endl;
		return;
	}

	if (!kernel32ModuleHandle)
	{
		cerr << "[parent] - Could not retrieve own kernel32.dll module" << endl;
		return;
	}

	memset(&ntdllModuleInfo, 0x0, sizeof(ntdllModuleInfo));

	if (!GetModuleInformation(GetCurrentProcess(), ntdllModuleHandle, &ntdllModuleInfo, sizeof(ntdllModuleInfo)))
		throw RuntimeException("Could not retrieve the own ntdll.dll module information");

	this->offsetRtlUserThreadStart = this->calculateSymbolOffset(ntdllModuleHandle, ntdllModuleInfo.lpBaseOfDll, "RtlUserThreadStart");
	this->offsetNtReadFile = this->calculateSymbolOffset(ntdllModuleHandle, ntdllModuleInfo.lpBaseOfDll, "NtReadFile");
	this->offsetNtWriteFile = this->calculateSymbolOffset(ntdllModuleHandle, ntdllModuleInfo.lpBaseOfDll, "NtWriteFile");
	this->offsetNtOpenFile = this->calculateSymbolOffset(ntdllModuleHandle, ntdllModuleInfo.lpBaseOfDll, "NtOpenFile");
	this->offsetNtCreateFile = this->calculateSymbolOffset(ntdllModuleHandle, ntdllModuleInfo.lpBaseOfDll, "NtCreateFile");

	memset(&kernel32ModuleInfo, 0x0, sizeof(kernel32ModuleInfo));

	if (!GetModuleInformation(GetCurrentProcess(), kernel32ModuleHandle, &kernel32ModuleInfo, sizeof(kernel32ModuleInfo)))
		throw RuntimeException("Could not retrieve the own kernel32.dll module information");

	// TODO: very unsafe, there is no guarantee that the DLLs are located at the same virtual address
	this->kernel32Base = kernel32ModuleInfo.lpBaseOfDll;

	this->offsetLoadLibraryA = this->calculateSymbolOffset(kernel32ModuleHandle, kernel32ModuleInfo.lpBaseOfDll, "LoadLibraryA");
	this->offsetGetCurrentProcess = this->calculateSymbolOffset(kernel32ModuleHandle, kernel32ModuleInfo.lpBaseOfDll, "GetCurrentProcess");
	this->offsetGetModuleHandleExA = this->calculateSymbolOffset(kernel32ModuleHandle, kernel32ModuleInfo.lpBaseOfDll, "GetModuleHandleExA");
	this->offsetGetProcAddress = this->calculateSymbolOffset(kernel32ModuleHandle, kernel32ModuleInfo.lpBaseOfDll, "GetProcAddress");
	this->offsetK32GetModuleInformation = this->calculateSymbolOffset(kernel32ModuleHandle, kernel32ModuleInfo.lpBaseOfDll, "K32GetModuleInformation");
}

size_t Injector::calculateSymbolOffset(HMODULE moduleHandle, void * moduleBaseAddress, const char * name) const
{
	FARPROC address = GetProcAddress(moduleHandle, name);

	if (!address)
		throw RuntimeException("Could not retrieve the function address");

	return (size_t)address - (size_t)moduleBaseAddress;
}

void Injector::loadLocalSymbols()
{
	this->pInspectDLL = (void(*)(InspectDLLContext*))this->loadLocalSymbol("inspectDLL");
	this->pLoadFunctionAddress = (void(*)(LoadFunctionAddressContext*))this->loadLocalSymbol("loadFunctionAddress");
}

void * Injector::loadLocalSymbol(const string & name)
{
	void * address;
	byte * pByte;
	int offset;

	cout << "[parent] - Loading local function \"" << name << "\"" << endl;

	// Retrieve the entry point address

	address = (void*)GetProcAddress(Injector::hCodeLibModule, name.c_str());
	if (!address)
		throw RuntimeException("Could not load local symbol");

	cout << "[parent]   - Found function at 0x" << COUT_HEX_32 << address << endl;

	// Verify if the address points to the function body or to a jump to the body;
	// calculate the address of the effective function body if necessary

	pByte = (byte*)address;
	if (pByte[0] == Assembler::JumpNear)
	{
		cout << "[parent]   - Found near jump at 0x" << COUT_HEX_32 << (size_t)pByte << endl;
		offset = *(int*)(pByte + 1);
		offset += 5; // Jump near instruction size
		address = (void*)(((size_t)address) + offset);
		cout << "[parent]   - Relocating local function according to offset 0x" << COUT_HEX_32 << offset << endl;
	}

	cout << "[parent] - Local function at 0x" << COUT_HEX_32 << address << endl;

	return address;
}

void Injector::prepareCodeCaves()
{
	// Target (RtlUserThreadStart)
	// 00000000770BB870 48 83 EC 48          sub         rsp,48h
	// 00000000770BB874 4C 8B C9             mov         r9, rcx

	this->cave_RtlUserThreadStart = this->createCodeCave(this->initialRIP, 64, 7);

	// Target (NtOpenFile)
	// 770DDF00 - 4C 8B D1              - mov r10,rcx
	// 770DDF03 - B8 30000000           - mov eax,00000030 { 48 }
	// 770DDF08 - 0F05                  - syscall 
	// 770DDF0A - C3                    - ret 
	// 770DDF0B - 0F1F 44 00 00         - nop [rax+rax+00]

	// Target (NtCreateFile)
	// 000000007753E12 | 4C 8B D1		| mov r10, rcx	|
	// 000000007753E12 | B8 52 00 00 00	| mov eax, 52	| 52:'R'
	// 000000007753E12 | 0F 05			| syscall		|
	// 000000007753E12 | C3				| ret			|

	this->cave_NtCreateFile = this->createCodeCave((void*)((size_t)this->ntdllBase + this->offsetNtCreateFile), 64, 8);

	// Absolute path: pointer to null-terminated (?) unicode string at RSP+A0
	// Unicode string: 2 bytes per character, null == {0x0, 0x0}
}

shared_ptr<CodeCave> Injector::createCodeCave(void * callAddress, size_t size, size_t sourceBytesToMove) const
{
	shared_ptr<CodeCave> cave = make_shared<CodeCave>(size);
	size_t offset;

	this->writeNop(cave->getRawData(), 0, cave->getSize());
	cave->setCaveAddress(this->process->allocateMemory(size));
	cave->setCallAddress(callAddress);
	cave->setReturnAddress((void*)((size_t)callAddress + sourceBytesToMove));
	cave->setSourceBytesToMove(sourceBytesToMove);

	// Write at the end of the cave, to allow space for the cave implementation
	offset = size - (sourceBytesToMove + JUMP_NEAR_SIZE);

	this->writeSourceBytes(cave->getRawData(), offset, cave);
	this->writeJumpNear(cave->getRawData(), offset + sourceBytesToMove,
		(void*)((size_t)cave->getCaveAddress() + offset + sourceBytesToMove),
		cave->getReturnAddress());

	/*cout << "[parent] - Prepared empty code cave at 0x" << COUT_HEX_32 << cave->getCaveAddress() << endl;
	cout << "           - Call at 0x" << COUT_HEX_32 << cave->getCallAddress() << endl;*/

	return cave;
}

void Injector::writeNop(byte * buffer, size_t offset, size_t count) const
{
	for (size_t i = 0; i < count; ++i)
		buffer[offset + i] = 0x90;

	/*cout << "[parent] - Wrote " << dec << count << " NOP bytes at offset 0x" <<
		COUT_HEX_32 << offset << endl;*/
}

void Injector::writeJumpNear(byte * buffer, size_t offset, void * source, void * destination) const
{
	// General notes:
	// EB:		Jump short	(jump -128 to 127 of the IP)
	// E9:		Jump near	(jump within the code segment)
	// FF/EA:	Jump far	(intersegment jump, same privilege level)

	// From 00330000:
	// JMP 76DF15E0 => E9 DB15AC76
	// Because dest 76DF15E0 - (00330000 + [5]) = 76AC15DB

	// From 00260000:
	// JMP 76DCC520 => E9 1BC5B676
	// Because dest 76DCC520 - (00260000 + [5]) = 0x76B6C51B

	// From 00330200:
	// JMP 00330000 => E9 FBFDFFFF
	// Because FFFFFFFF - (00330200 + [4/5] - 00330000) = 0xFFFFFDFB
	// * Why -1?

	const size_t instructionSize = 5;
	size_t addressOffset;
	byte * addressOffsetBytes = (byte*)&addressOffset;

	buffer[offset] = 0xE9;

	if ((size_t)destination >= (size_t)source)
	{
		//cout << "[parent] - destination >= source" << endl;
		addressOffset = (size_t)destination - ((size_t)source + instructionSize);
	}
	else
	{
		//cout << "[parent] - destination < source" << endl;
		addressOffset = 0xFFFFFFFF - ((size_t)source + instructionSize - 1 - (size_t)destination);
	}

	buffer[offset + 1] = addressOffsetBytes[0];
	buffer[offset + 2] = addressOffsetBytes[1];
	buffer[offset + 3] = addressOffsetBytes[2];
	buffer[offset + 4] = addressOffsetBytes[3];

	/*cout << "[parent] - Wrote " << dec << instructionSize << " jump bytes at offset 0x" <<
		COUT_HEX_32 << offset << endl;*/
}

void Injector::writeSourceBytes(byte * buffer, size_t offset, shared_ptr<CodeCave> codeCave) const
{
	byte * localBuffer = new byte[codeCave->getSourceBytesToMove()];
	this->process->readMemory(codeCave->getCallAddress(), localBuffer, codeCave->getSourceBytesToMove());

	for (size_t i = 0; i < codeCave->getSourceBytesToMove(); ++i)
		buffer[offset + i] = localBuffer[i];

	delete[] localBuffer;

	/*cout << "[parent] - Wrote " << dec << codeCave->getSourceBytesToMove() << " source bytes at offset 0x" <<
		COUT_HEX_32 << offset << endl;*/
}

void Injector::inject(shared_ptr<CodeCave> codeCave)
{
	byte * jumpToCave;

	if (!codeCave.get())
		return;

	cout << "[parent] - Performing injections" << endl;

	this->process->writeMemory(codeCave->getRawData(), codeCave->getSize(), codeCave->getCaveAddress());

	cout << "[parent]   - Injected " << dec << codeCave->getSize() << " bytes at 0x" <<
		COUT_HEX_32 << codeCave->getCaveAddress() << endl;

	jumpToCave = new byte[codeCave->getSourceBytesToMove()];
	writeNop(jumpToCave, 0, codeCave->getSourceBytesToMove());
	writeJumpNear(jumpToCave, 0, codeCave->getCallAddress(), codeCave->getCaveAddress());
	this->process->writeMemory(jumpToCave, codeCave->getSourceBytesToMove(), codeCave->getCallAddress());
	delete[] jumpToCave;

	cout << "[parent]   - Injected " << dec << codeCave->getSourceBytesToMove() << " bytes at 0x" <<
		COUT_HEX_32 << codeCave->getCallAddress() << endl;
	cout << "[parent] - Injections performed" << endl;
}

shared_ptr<DLL> Injector::inspectInjectedDLL(const string & fileName, const void * fileNameAddress)
{
	shared_ptr<DLL> dll;
	InspectDLLContext inspectContext;

	memset(&inspectContext, 0x0, sizeof(inspectContext));

	inspectContext.dllName = (const char *)fileNameAddress;
	inspectContext.pGetCurrentProcess = (HANDLE(*)())
		((size_t)this->kernel32Base + this->offsetGetCurrentProcess);
	inspectContext.pGetModuleHandleEx = (bool(*)(DWORD, LPCSTR, HMODULE*))
		((size_t)this->kernel32Base + this->offsetGetModuleHandleExA);
	inspectContext.pGetModuleInformation = (bool(*)(HANDLE, HMODULE, LPMODULEINFO, DWORD))
		((size_t)this->kernel32Base + this->offsetK32GetModuleInformation);

	this->executeLocalFunctionRemotely(this->pInspectDLL,
		&inspectContext, sizeof(inspectContext));

	dll = make_shared<DLL>(fileName, inspectContext.hModule, inspectContext.moduleBaseAddress);

	cout << "[parent] - Module base address: 0x" << COUT_HEX_32 << inspectContext.moduleBaseAddress << endl;

	return dll;
}

void Injector::inspectInjectedDLL(void * address)
{
	// TODO: experimental implementation

	InspectStealthDLLContext context;
	void * contextAddress;
	void * remoteFunctionAddress;
	MODULEINFO moduleInfo;

	context.moduleBaseAddress = address;

	// Define the API function addresses that will be used by CodeLib
	context.pGetModuleHandleEx = (bool(*)(DWORD, LPCSTR, HMODULE*))
		((size_t)this->kernel32Base + this->offsetGetModuleHandleExA);
	context.pGetProcAddress = (FARPROC(*)(HMODULE, LPCSTR))
		((size_t)this->kernel32Base + this->offsetGetProcAddress);

	contextAddress = this->process->allocateMemory(sizeof(context));
	this->process->writeMemory(&context, sizeof(context), contextAddress);
	cout << "[parent] - Context written at 0x" << COUT_HEX_32 << contextAddress << endl;

	remoteFunctionAddress = this->injectLocalFunction(this->pInspectDLL);

	cout << "[parent]   - Spawning thread at 0x" << COUT_HEX_32 << remoteFunctionAddress << endl;
	cin.get();
	this->process->spawnThread(remoteFunctionAddress, contextAddress);

	this->process->readMemory(contextAddress, &context, sizeof(context));
	cout << "[parent] - Retrieved hModule: 0x" << COUT_HEX_32 << context.hModule << endl;

	/*this->process->getModuleInfo(context.hModule, &moduleInfo);
	cout << "[parent] - Retrieved module base address: 0x" << COUT_HEX_32 << moduleInfo.lpBaseOfDll << endl;*/
}

void * Injector::injectLocalFunction(const void * function)
{
	// TODO: a fixed function size is highly inflexible,
	// but it's complicated to programmatically retrieve a function size
	const size_t functionSize = 512;

	void * address = this->process->allocateMemory(functionSize);

	//cout << "[parent] - Local function at 0x" << COUT_HEX_32 << function << endl;
	//cout << "[parent] - Injecting function at 0x" << COUT_HEX_32 << address << endl;

	// NOTE: Win32 function addresses are not necessarily valid in the target process's virtual address space
	this->process->writeMemory(function, functionSize, address);

	cout << "[parent] - Injected function at 0x" << COUT_HEX_32 << address << endl;

	return address;
}