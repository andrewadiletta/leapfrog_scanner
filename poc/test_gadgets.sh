#!/bin/bash
PIN_PATH="/home/andrew/Jumbo_Flip/pin/pin-3.28-98749-g6643ecee5-gcc-linux/pin"
TOOL_PATH="/home/andrew/Jumbo_Flip/pin/pin-3.28-98749-g6643ecee5-gcc-linux/source/tools/ManualExamples/obj-intel64/itrace_simulate_caner.so"

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