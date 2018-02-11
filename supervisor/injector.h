#ifndef _INJECTOR_H_
#define _INJECTOR_H_

#include <vector>
#include "process.h"
#include "codecave.h"

class Injector
{
	public:
		Injector(std::shared_ptr<Process> process);
		virtual ~Injector() noexcept(false);

		virtual void performInjections();
	
	protected:
		std::shared_ptr<Process> process;
		void * initialRIP;
		void * ntdllBase;
		size_t offsetRtlUserThreadStart;
		size_t offsetNtReadFile;
		size_t offsetNtWriteFile;
		size_t offsetNtOpenFile;
		//std::shared_ptr<std::vector<CodeCave>> codeCaves;

		std::shared_ptr<CodeCave> cave_RtlUserThreadStart;
		std::shared_ptr<CodeCave> cave_NtOpenFile;

		virtual void analyzeProcess();
		virtual void calculateSymbolOffsets();
		virtual size_t calculateSymbolOffset(HMODULE moduleHandle, void * moduleBaseAddress, const char * name) const;
		virtual void prepareCodeCaves();
		virtual std::shared_ptr<CodeCave> createCodeCave(void * callAddress, size_t size, size_t sourceBytesToMove) const;
		virtual void writeNop(byte * buffer, size_t offset, size_t count) const;
		virtual void writeJumpNear(byte * buffer, size_t offset, void * source, void * destination) const;
		virtual void writeSourceBytes(byte * buffer, size_t offset, std::shared_ptr<CodeCave> codeCave) const;
		virtual void inject(std::shared_ptr<CodeCave> codeCave);
};

#endif