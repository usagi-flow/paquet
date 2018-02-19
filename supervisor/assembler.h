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
	static const Register RBP = 5;
	static const Register RSP = 6;
	static const Register RSI = 7;
	static const Register RDI = 8;

	static const OpCode JumpNear = 0xE9;

	Assembler();
	virtual ~Assembler() noexcept(false);

	static size_t writeNop(byte * buffer, size_t offset, size_t count);
	static size_t writePush(byte * buffer, size_t offset, Register operand);
	static size_t writePop(byte * buffer, size_t offset, Register operand);
	static size_t writeRet(byte * buffer, size_t offset);
	static size_t writeJumpNear(byte * buffer, size_t offset, void * source, void * destination);
	static size_t writeCallNear(byte * buffer, size_t offset, void * source, void * destination);
	static size_t writeCallReg(byte * buffer, size_t offset, Register operand);
	static size_t writeMovReg(byte * buffer, size_t offset, Register operand, size_t value);

protected:
};

#endif