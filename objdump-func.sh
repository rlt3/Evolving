#!/bin/bash
# object dump a particular function 
# $1 = the binary
# $2 = the function name
gdb -batch -ex "file $1" -ex "disassemble/rs $2"
