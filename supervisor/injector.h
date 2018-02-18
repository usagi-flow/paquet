#ifndef _INJECTOR_H_
#define _INJECTOR_H_

#include <fstream>
#include <string>
#include "process.h"
#include "codecave.h"
#include "assembler.h"
#include "../codelib/codelib.h"

class Injector
{
	public:
		Injector(std::shared_ptr<Process> process);
		virtual ~Injector() noexcept(false);

		virtual void prepare();
		virtual void performInjections();
		virtual void injectDLL(const std::string & fileName);
		virtual void injectDLLStealthed(const std::string & fileName);
		virtual void executeLocalFunctionRemotely(void * function, void * context);
	
	protected:
		static HMODULE hCodeLibModule;

		std::shared_ptr<Process> process;
		void * initialRIP;
		void * ntdllBase;
		void * kernel32Base;
		size_t offsetRtlUserThreadStart;
		size_t offsetNtReadFile;
		size_t offsetNtWriteFile;
		size_t offsetNtOpenFile;
		size_t offsetNtCreateFile;
		size_t offsetGetModuleHandleExA;
		size_t offsetGetProcAddress;
		size_t offsetLoadLibraryA;
		size_t offsetK32GetModuleInformation;
		//std::shared_ptr<std::vector<CodeCave>> codeCaves;
		byte * dllBuffer;
		size_t dllSize;

		void (*pInspectDLL)(InspectDLLContext * context);

		std::shared_ptr<CodeCave> cave_RtlUserThreadStart;
		std::shared_ptr<CodeCave> cave_NtOpenFile;
		std::shared_ptr<CodeCave> cave_NtCreateFile;

		virtual void loadCodeLib();
		virtual void analyzeProcess();
		virtual void calculateSymbolOffsets();
		virtual size_t calculateSymbolOffset(HMODULE moduleHandle, void * moduleBaseAddress, const char * name) const;
		virtual void loadOwnSymbols();
		virtual void prepareCodeCaves();
		virtual std::shared_ptr<CodeCave> createCodeCave(void * callAddress, size_t size, size_t sourceBytesToMove) const;
		virtual void writeNop(byte * buffer, size_t offset, size_t count) const;
		virtual void writeJumpNear(byte * buffer, size_t offset, void * source, void * destination) const;
		virtual void writeSourceBytes(byte * buffer, size_t offset, std::shared_ptr<CodeCave> codeCave) const;
		virtual void inject(std::shared_ptr<CodeCave> codeCave);

		virtual void inspectInjectedDLL(const std::string & fileName, const void * fileNameAddress);
		virtual void inspectInjectedDLL(void * address);
		virtual void * injectLocalFunction(const void * function);
};

#endif