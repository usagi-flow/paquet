#include "dll.h"

using namespace std;

DLL::DLL(const string & name, HMODULE hModule, void * baseAddress)
{
	this->name = name;
	this->hModule = hModule;
	this->baseAddress = baseAddress;
}

DLL::~DLL() noexcept(false)
{
}

string DLL::getName() const
{
	return this->name;
}

HMODULE DLL::getHandle() const
{
	return this->hModule;
}

void * DLL::getBaseAddress() const
{
	return this->baseAddress;
}