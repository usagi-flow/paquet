#include "assembler.h"

Assembler::Assembler()
{
}

Assembler::~Assembler() noexcept(false)
{
}

size_t Assembler::writeNop(byte * buffer, size_t offset, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		buffer[offset + i] = 0x90;

	return 1;
}

size_t Assembler::writePush(byte * buffer, size_t offset, Register operand)
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

	return 1;
}

size_t Assembler::writePop(byte * buffer, size_t offset, Register operand)
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

	return 1;
}

size_t Assembler::writeRet(byte * buffer, size_t offset)
{
	buffer[offset] = 0xC3;

	return 1;
}

size_t Assembler::writeJumpNear(byte * buffer, size_t offset, void * source, void * destination)
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

	return 5;
}

size_t Assembler::writeCallNear(byte * buffer, size_t offset, void * source, void * destination)
{
	Assembler::writeJumpNear(buffer, offset, source, destination);
	buffer[offset] = 0xE8;

	return 2;
}

size_t Assembler::writeCallReg(byte * buffer, size_t offset, Register operand)
{
	byte code = 0x90;

	switch (operand)
	{
	case Assembler::RAX:
		code = 0xD0;
		break;
	case Assembler::RBX:
		code = 0xD3;
		break;
	case Assembler::RCX:
		code = 0xD1;
		break;
	case Assembler::RDX:
		code = 0xD2;
		break;
	default:
		throw RuntimeException("Unsupported operand");
		break;
	}

	buffer[offset] = 0xFF;
	buffer[offset + 1] = code;

	return 2;
}

size_t Assembler::writeMovReg(byte * buffer, size_t offset, Register operand, size_t value)
{
	byte regOperand = 0x90;
	size_t i = 0;

	switch (operand)
	{
	case Assembler::RAX:
		regOperand = 0xB8;
		break;
	case Assembler::RBX:
		regOperand = 0xBB;
		break;
	case Assembler::RCX:
		regOperand = 0xB9;
		break;
	case Assembler::RDX:
		regOperand = 0xBA;
		break;
	default:
		throw RuntimeException("Unsupported operand");
		break;
	}

	buffer[offset + i++] = 0x48;
	buffer[offset + i++] = regOperand;
	buffer[offset + i++] = ((byte*)&value)[0];
	buffer[offset + i++] = ((byte*)&value)[1];
	buffer[offset + i++] = ((byte*)&value)[2];
	buffer[offset + i++] = ((byte*)&value)[3];
	buffer[offset + i++] = ((byte*)&value)[4];
	buffer[offset + i++] = ((byte*)&value)[5];
	buffer[offset + i++] = ((byte*)&value)[6];
	buffer[offset + i++] = ((byte*)&value)[7];

	return i;
}