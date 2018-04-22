#include "runtime-exception.h"

RuntimeException::RuntimeException(const char * message)
{
	this->message = message;
}

RuntimeException::~RuntimeException()
{
}

const char * RuntimeException::what() const throw()
{
	return this->message;
}