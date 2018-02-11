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
		//std::shared_ptr<std::vector<CodeCave>> codeCaves;

		std::shared_ptr<CodeCave> cave_RtlUserThreadStart;
		std::shared_ptr<CodeCave> cave_NtOpenFile;

		virtual void analyzeProcess();
		virtual void prepareCodeCaves();
		virtual void writeNop(byte * buffer, size_t offset, size_t count);
		virtual void writeJumpNear(byte * buffer, size_t offset, void * source, void * destination);
		virtual void writeSourceBytes(byte * buffer, size_t offset, std::shared_ptr<CodeCave> codeCave);
		virtual void inject(std::shared_ptr<CodeCave> codeCave);
};

#endif