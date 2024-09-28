#!/bin/bash
PIN_PATH="../pin-3.28/pin"
TOOL_PATH="../pin-3.28/source/tools/ManualExamples/obj-intel64/itrace_simulate.so"

COMMAND="poc_binary/poc_binary"

# make the working directory the directory this script is in
cd "$(dirname "$0")"


# disable ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

if [ $# -eq 2 ]; then
    # If there are two arguments, use them as source and target
    $PIN_PATH -t $TOOL_PATH -source $1 -target $2 -- $COMMAND
else
    # Otherwise, run without source and target
    $PIN_PATH -t $TOOL_PATH -- $COMMAND
fi

python fix_return_addresses.py