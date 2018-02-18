#ifndef _ASSEMBLER_H_
#define _ASSEMBLER_H_

#include "macros.h"
#include "typedef.h"
#include "runtime-exception.h"

typedef unsigned short Register;
typedef byte OpCode;

class Assembler
{
public:
	static const Register RAX = 1;
	static const Register RBX = 2;
	static const Register RCX = 3;
	static const Register RDX = 4;

	static const OpCode JumpNear = 0xE9;

	Assembler();
	virtual ~Assembler() noexcept(false);

	static void writeNop(byte * buffer, size_t offset, size_t count);
	static void writePush(byte * buffer, size_t offset, Register operand);
	static void writePop(byte * buffer, size_t offset, Register operand);
	static void writeRet(byte * buffer, size_t offset);
	static void writeJumpNear(byte * buffer, size_t offset, void * source, void * destination);

protected:
};

#endif