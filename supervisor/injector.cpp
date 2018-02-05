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
	this->analyzeProcess();
	this->prepareCodeCaves();
	//this->inject(this->cave_NtOpenFile);
	this->inject(this->cave_RtlUserThreadStart);
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
	this->writeJumpNear(this->cave_RtlUserThreadStart, i, address, this->initialRIP);
}

void Injector::inject(std::shared_ptr<CodeCave> codeCave)
{
	/*void * address = this->process->allocateMemory(codeCave->getSize());

	codeCavecodeCave->setAddress(address);*/

	this->process->writeMemory(codeCave->getRawData(), codeCave->getSize(), codeCave->getAddress());

	cout << "[parent] - Injected " << dec << codeCave->getSize() << " bytes at 0x" <<
		dec << COUT_HEX_32 << codeCave->getAddress() << endl;
}

void Injector::writeJumpNear(std::shared_ptr<CodeCave>, size_t & index, void * source, void * destination)
{
}