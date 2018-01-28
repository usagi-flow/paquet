#!/bin/sh

dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $dir && \
	cmake . && cmake --build . && echo && ./wintest.exe && cat file.txt

echo
echo "Process terminated with return code $?"