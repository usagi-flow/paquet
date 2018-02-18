#include "assembler.h"

Assembler::Assembler()
{
}

Assembler::~Assembler() noexcept(false)
{
}

void Assembler::writeNop(byte * buffer, size_t offset, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		buffer[offset + i] = 0x90;
}

void Assembler::writePush(byte * buffer, size_t offset, Register operand)
{
	byte code = 0x90;

	switch (operand)
	{
	case Assembler::RAX:
		code = 0x50;
		break;
	case Assembler::RBX:
		code = 0x53;
		break;
	case Assembler::RCX:
		code = 0x51;
		break;
	case Assembler::RDX:
		code = 0x52;
		break;
	default:
		throw RuntimeException("Unsupported operand");
		break;
	}

	buffer[offset] = code;
}

void Assembler::writePop(byte * buffer, size_t offset, Register operand)
{
	byte code = 0x90;

	switch (operand)
	{
	case Assembler::RAX:
		code = 0x58;
		break;
	case Assembler::RBX:
		code = 0x5B;
		break;
	case Assembler::RCX:
		code = 0x59;
		break;
	case Assembler::RDX:
		code = 0x5A;
		break;
	default:
		throw RuntimeException("Unsupported operand");
		break;
	}

	buffer[offset] = code;
}

void Assembler::writeRet(byte * buffer, size_t offset)
{
	buffer[offset] = 0xC3;
}

void Assembler::writeJumpNear(byte * buffer, size_t offset, void * source, void * destination)
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
		addressOffset = (size_t)destination - ((size_t)source + instructionSize);
	else
		addressOffset = 0xFFFFFFFF - ((size_t)source + instructionSize - 1 - (size_t)destination);

	buffer[offset + 1] = addressOffsetBytes[0];
	buffer[offset + 2] = addressOffsetBytes[1];
	buffer[offset + 3] = addressOffsetBytes[2];
	buffer[offset + 4] = addressOffsetBytes[3];
}