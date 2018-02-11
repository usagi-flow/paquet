#include "injector.h"

// Defined offsets
#define JUMP_NEAR_SIZE	0x5

using namespace std;

Injector::Injector(std::shared_ptr<Process> process)
{
	this->process = process;
	this->initialRIP = 0x0;
	this->ntdllBase;
	this->offsetNtOpenFile = 0x0;
	this->offsetNtWriteFile = 0x0;
	this->offsetRtlUserThreadStart = 0x0;

	cout << "[parent] * Initialized Injector instance @ 0x" << COUT_HEX_32 << this << endl;
	cout << "[parent] * Process image name: " << this->process->getName() << endl;
}

Injector::~Injector() noexcept(false)
{
}

void Injector::performInjections()
{
	void * address;
	byte jumpInstruction[] = {0x0, 0x0, 0x0, 0x0, 0x0};

	this->analyzeProcess();
	this->prepareCodeCaves();

	// Inject the code caves
	this->inject(this->cave_RtlUserThreadStart);
	this->inject(this->cave_NtOpenFile);

	// Write jump to code cave
	//this->writeJumpNear(jumpInstruction, 0, this->initialRIP, this->cave_RtlUserThreadStart->getCaveAddress());
	//this->process->writeMemory(jumpInstruction, sizeof(jumpInstruction), this->initialRIP);
}

void Injector::analyzeProcess()
{
	cout << "[parent] - Analyzing memory" << endl;

	this->initialRIP = (void*)this->process->getMainThreadContext()->Rip;
	this->calculateSymbolOffsets();
	this->ntdllBase = (void*)((size_t)this->initialRIP - this->offsetRtlUserThreadStart);

	cout << "[parent] - Initial RIP:            0x" << COUT_HEX_32 << this->initialRIP << endl;
	cout << "[parent] - Calculated ntdll base:  0x" << COUT_HEX_32 << this->ntdllBase << endl;

	cout << "[parent] - ntdll.dll!NtReadFile:   0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtReadFile) << endl;
	cout << "[parent] - ntdll.dll!NtWriteFile:  0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtWriteFile) << endl;
	cout << "[parent] - ntdll.dll!NtOpenFile:   0x" << COUT_HEX_32 <<
		((size_t)this->ntdllBase + this->offsetNtOpenFile) << endl;
}

void Injector::calculateSymbolOffsets()
{
	HMODULE moduleHandle = GetModuleHandle("ntdll.dll");

	MODULEINFO moduleInfo;
	//FARPROC openFileAddress = GetProcAddress(moduleHandle, "NtOpenFile");
	//FARPROC threadStartAddress = GetProcAddress(moduleHandle, "RtlUserThreadStart");

	if (!moduleHandle)
	{
		cerr << "[parent] - Could not retrieve own ntdll.dll module" << endl;
		return;
	}

	memset(&moduleInfo, 0x0, sizeof(moduleInfo));

	if (!GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo)))
		throw RuntimeException("Could not retrieve the own ntdll.dll module information");

	this->offsetRtlUserThreadStart = this->calculateSymbolOffset(moduleHandle, moduleInfo.lpBaseOfDll, "RtlUserThreadStart");
	this->offsetNtReadFile = this->calculateSymbolOffset(moduleHandle, moduleInfo.lpBaseOfDll, "NtReadFile");
	this->offsetNtWriteFile = this->calculateSymbolOffset(moduleHandle, moduleInfo.lpBaseOfDll, "NtWriteFile");
	this->offsetNtOpenFile = this->calculateSymbolOffset(moduleHandle, moduleInfo.lpBaseOfDll, "NtOpenFile");
}

size_t Injector::calculateSymbolOffset(HMODULE moduleHandle, void * moduleBaseAddress, const char * name) const
{
	FARPROC address = GetProcAddress(moduleHandle, name);

	if (!address)
		throw RuntimeException("Could not retrieve the function address");

	return (size_t)address - (size_t)moduleBaseAddress;
}

void Injector::prepareCodeCaves()
{
	shared_ptr<CodeCave> cave;
	size_t size;
	size_t bytesToMove;

	// Target:
	// 00000000770BB870 48 83 EC 48          sub         rsp,48h
	// 00000000770BB874 4C 8B C9             mov         r9, rcx

	size = 512;
	bytesToMove = 7;

	cave = make_shared<CodeCave>(size);

	this->writeNop(cave->getRawData(), 0, cave->getSize());
	cave->setCaveAddress(this->process->allocateMemory(size));
	cave->setCallAddress(this->initialRIP);
	cave->setReturnAddress((void*)((size_t)this->initialRIP + bytesToMove));
	cave->setSourceBytesToMove(bytesToMove);

	this->writeSourceBytes(cave->getRawData(), 0, cave);
	this->writeJumpNear(cave->getRawData(), bytesToMove,
		(void*)((size_t)cave->getCaveAddress() + bytesToMove),
		cave->getReturnAddress());

	this->cave_RtlUserThreadStart = cave;

	// Target (NtOpenFile)
	// 770DDF00 - 4C 8B D1              - mov r10,rcx
	// 770DDF03 - B8 30000000           - mov eax,00000030 { 48 }
	// 770DDF08 - 0F05                  - syscall 
	// 770DDF0A - C3                    - ret 
	// 770DDF0B - 0F1F 44 00 00         - nop [rax+rax+00]

	this->cave_NtOpenFile = this->createCodeCave((void*)((size_t)this->ntdllBase + this->offsetNtOpenFile), 512, 8);
}

shared_ptr<CodeCave> Injector::createCodeCave(void * callAddress, size_t size, size_t sourceBytesToMove) const
{
	shared_ptr<CodeCave> cave = make_shared<CodeCave>(size);

	this->writeNop(cave->getRawData(), 0, cave->getSize());
	cave->setCaveAddress(this->process->allocateMemory(size));
	cave->setCallAddress(callAddress);
	cave->setReturnAddress((void*)((size_t)callAddress + sourceBytesToMove));
	cave->setSourceBytesToMove(sourceBytesToMove);

	this->writeSourceBytes(cave->getRawData(), 0, cave);
	this->writeJumpNear(cave->getRawData(), sourceBytesToMove,
		(void*)((size_t)cave->getCaveAddress() + sourceBytesToMove),
		cave->getReturnAddress());

	cout << "[parent] - Prepared empty code cave at 0x" << COUT_HEX_32 << cave->getCaveAddress() << endl;

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

	this->process->writeMemory(codeCave->getRawData(), codeCave->getSize(), codeCave->getCaveAddress());

	cout << "[parent] - Injected " << dec << codeCave->getSize() << " bytes at 0x" <<
		COUT_HEX_32 << codeCave->getCaveAddress() << endl;

	jumpToCave = new byte[codeCave->getSourceBytesToMove()];
	writeNop(jumpToCave, 0, codeCave->getSourceBytesToMove());
	writeJumpNear(jumpToCave, 0, this->initialRIP, codeCave->getCaveAddress());
	this->process->writeMemory(jumpToCave, codeCave->getSourceBytesToMove(), this->initialRIP);
	delete[] jumpToCave;

	cout << "[parent] - Injected " << dec << codeCave->getSourceBytesToMove() << " bytes at 0x" <<
		COUT_HEX_32 << this->initialRIP << endl;
}