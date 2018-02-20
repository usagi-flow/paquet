#ifndef _RUNTIME_EXCEPTION_H_
#define _RUNTIME_EXCEPTION_H_

#include <exception>

class RuntimeException : public std::exception
{
	public:
		RuntimeException(const char * message);
		virtual ~RuntimeException();

		virtual const char* what() const throw();

	protected:
		const char * message;
};

#endif