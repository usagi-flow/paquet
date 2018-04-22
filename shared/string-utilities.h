#ifndef _STRING_UTILITIES_H_
#define _STRING_UTILITIES_H_

#include <string>
#include <memory>

class StringUtilities
{
public:
	virtual ~StringUtilities();

	static bool startsWith(const std::string & value, const std::string & prefix);
	static bool endsWith(const std::string & value, const std::string & suffix);

	static bool startsWith(const std::wstring & value, const std::wstring & prefix);
	static bool endsWith(const std::wstring & value, const std::wstring & suffix);

	static std::shared_ptr<std::wstring> toWString(const std::string & source);
	static void toWCString(const char * source, wchar_t * destination, size_t stringLength);

protected:
	const char * message;

	StringUtilities();
};

#endif