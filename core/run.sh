#!/bin/sh

dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export CC=x86_64-w64-mingw32-clang
export CXX=x86_64-w64-mingw32-clang++

cd $dir && \
	cmake . && cmake --build . && echo && ./wintest.exe

returnCode=$?

echo
echo "Process terminated with return code $returnCode"
cat $dir/file.txt
