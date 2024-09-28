binary_file="../poc_binary/poc_binary"

if [ -f "$binary_file" ]; then
    gdb -q "$binary_file" -x gdb_commands > asm_dump.asm
else
    echo "Binary file does not exist."
fi