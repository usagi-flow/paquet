#ifndef _DLL_H_
#define _DLL_H_

#include <string>
#include <windows.h>

class DLL
{
public:
	DLL(const std::string & name, HMODULE hModule, void * baseAddress);
	virtual ~DLL() noexcept(false);

	virtual std::string getName() const;
	virtual HMODULE getHandle() const;
	virtual void * getBaseAddress() const;

protected:
	std::string name;
	HMODULE hModule;
	void * baseAddress;
};

#endif