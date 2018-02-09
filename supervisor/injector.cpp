#include "injector.h"

// Defined offsets
#define NTDLL_RtlUserThreadStart	0x0002C520
#define NTDLL_NtReadFile			0x00051310
#define NTDLL_NtWriteFile			0x00051330
#define NTDLL_NtOpenFile			0x000515E0
#define NTDLL_NtCreateFile			0x00051800

using namespace std;

Injector::Injector(std::shared_ptr<Process> process)
{
	this->process = process;
	this->initialRIP = 0x0;
	this->ntdllBase = 0x0;

	cout << "[parent] * Initialized Injector instance @ 0x" << COUT_HEX_32 << this << endl;
	cout << "[parent] * Process image name: " << this->process->getName() << endl;

	CodeCave codeCave = CodeCave(0x0, 5); // TODO: temp
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

	//this->inject(this->cave_NtOpenFile);

	// Write code cave with jump back to initialRIP + 5
	this->inject(this->cave_RtlUserThreadStart);

	// Write jump to code cave
	this->writeJumpNear(jumpInstruction, 0, this->initialRIP, this->cave_RtlUserThreadStart->getAddress());
	//this->process->writeMemory(jumpInstruction, sizeof(jumpInstruction), this->initialRIP);
}

void Injector::analyzeProcess()
{
	cout << "[parent] - Analyzing memory" << endl;

	this->initialRIP = (void*)this->process->getMainThreadContext()->Rip;
	this->ntdllBase = (void*)((unsigned long)this->initialRIP - (unsigned long)NTDLL_RtlUserThreadStart);

	cout << "[parent] - Initial RIP:            0x" << COUT_HEX_32 << this->initialRIP << endl;
	cout << "[parent] - Calculated ntdll base:  0x" << COUT_HEX_32 << this->ntdllBase << endl;

	cout << "[parent] - ntdll.dll!NtReadFile:   0x" << COUT_HEX_32 <<
		((unsigned long)this->ntdllBase + NTDLL_NtReadFile) << endl;
	cout << "[parent] - ntdll.dll!NtWriteFile:  0x" << COUT_HEX_32 <<
		((unsigned long)this->ntdllBase + NTDLL_NtWriteFile) << endl;
	cout << "[parent] - ntdll.dll!NtOpenFile:   0x" << COUT_HEX_32 <<
		((unsigned long)this->ntdllBase + NTDLL_NtOpenFile) << endl;
}

void Injector::prepareCodeCaves()
{
	size_t size;
	size_t i;
	void * address;

	//this->cave_NtOpenFile = make_shared<CodeCave>(512);

	size = 512;
	i = 0;
	address = this->process->allocateMemory(size);

	this->cave_RtlUserThreadStart = make_shared<CodeCave>(size);
	this->cave_RtlUserThreadStart->setAddress(address);
	this->writeJumpNear(this->cave_RtlUserThreadStart->getRawData(), i, address, (void*)((size_t)this->initialRIP + 5));
}

void Injector::writeJumpNear(byte * buffer, size_t offset, void * source, void * destination)
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
		cout << "[parent] - destination >= source" << endl;
		addressOffset = (size_t)destination - ((size_t)source + instructionSize);
	}
	else
	{
		cout << "[parent] - destination < source" << endl;
		addressOffset = 0xFFFFFFFF - ((size_t)source + instructionSize - 1 - (size_t)destination);
	}

	buffer[offset + 1] = addressOffsetBytes[0];
	buffer[offset + 2] = addressOffsetBytes[1];
	buffer[offset + 3] = addressOffsetBytes[2];
	buffer[offset + 4] = addressOffsetBytes[3];
}

void Injector::inject(shared_ptr<CodeCave> codeCave)
{
	this->process->writeMemory(codeCave->getRawData(), codeCave->getSize(), codeCave->getAddress());

	cout << "[parent] - Injected " << dec << codeCave->getSize() << " bytes at 0x" <<
		dec << COUT_HEX_32 << codeCave->getAddress() << endl;

}