#include <stdio.h>
#include <string>
#include <vector>
#include "pin.H"

using std::string;
using std::vector;

FILE* trace_file;
FILE* return_addresses_file;
vector<ADDRINT> return_addresses;
unsigned long long int source_addr = 0;
unsigned long long int target_addr = 0;
bool fault_injection_mode = false;

KNOB<string> KnobSourceAddr(KNOB_MODE_WRITEONCE, "pintool", "source", "0", "Source address for fault injection");
KNOB<string> KnobTargetAddr(KNOB_MODE_WRITEONCE, "pintool", "target", "0", "Target address for fault injection");

VOID RecordTrace(VOID * ip) {
    fprintf(trace_file, "%p\n", ip);
     //fprintf(trace_file, "%p: %s\n", ip, disassembly.c_str());
}

VOID RecordReturnAddress(ADDRINT addr) {
    fprintf(return_addresses_file, "%lx\n", addr);
    //fprintf(trace_file, "%p: %s\n", ip, disassembly.c_str());
    
}

VOID SimulateFault(INS ins, VOID *v) {
    if (INS_Address(ins)+ INS_Size(ins) == source_addr) {
        INS_InsertDirectJump(ins, IPOINT_BEFORE, target_addr);
    }
}

VOID Instruction(INS ins, VOID *v) {
    // Always record trace
    //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordTrace, IARG_INST_PTR, IARG_END);

    if (fault_injection_mode) {
        SimulateFault(ins, v);
    } else {
        string ins_str = INS_Disassemble(ins);
        fprintf(trace_file, "%p: %s\n", (void*)INS_Address(ins), ins_str.c_str());
        if (INS_IsCall(ins)) {
            ADDRINT return_addr = INS_Address(ins) + INS_Size(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordReturnAddress,
                           IARG_ADDRINT, return_addr, IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v) {
    if (return_addresses_file)
        fclose(return_addresses_file);
    if (trace_file)
        fclose(trace_file);
}

int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;

    string source_str = KnobSourceAddr.Value();
    string target_str = KnobTargetAddr.Value();

    // Always open trace file
    trace_file = fopen("itrace.out", "w");
    if (!trace_file) {
        perror("Failed to open itrace.out");
        return 1;
    }

    if (source_str != "0" && target_str != "0") {
        // Fault injection mode
        fault_injection_mode = true;
        source_addr = std::stoull(source_str, nullptr, 16);
        target_addr = std::stoull(target_str, nullptr, 16);
        printf("Fault injection mode: source = 0x%llx, target = 0x%llx\n", source_addr, target_addr);
    } else {
        // Return address collection mode
        return_addresses_file = fopen("return_addresses.out", "w");
        if (!return_addresses_file) {
            perror("Failed to open return_addresses.out");
            return 1;
        }
        printf("Return address collection mode\n");
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}