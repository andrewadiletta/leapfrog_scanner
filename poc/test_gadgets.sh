#!/bin/bash
PIN_PATH="PIN_PATH/HERE/pin"
TOOL_PATH="PIN_PATH/HERE/source/tools/ManualExamples/obj-intel64/itrace_simulate_caner.so"

COMMAND="poc_binary/poc_binary"

# make the working directory the directory this script is in
cd "$(dirname "$0")"

# disable ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

echo $'\n'Simulating the potential gadgets...$'\n'
cmd="$PIN_PATH -t $TOOL_PATH -- $COMMAND > simulation_results.out"
echo $cmd
eval $cmd
pwd
