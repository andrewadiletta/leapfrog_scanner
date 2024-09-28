#include <stdio.h>
#include <string>
#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <unordered_map>
#include <fcntl.h>
#include <unistd.h>

using std::string;

// Global variables
FILE* trace;
const char* outputFile = "stdout_redirect.txt";
int redirectedFD = -1;
const int MAX_BIT_FLIP = 4;  // Only flip the first 4 bits
std::ofstream logFile;
std::unordered_map<ADDRINT, int> addressBitFlips;

// Function prototypes
VOID Instruction(INS ins, VOID* v);
ADDRINT FlipBit(ADDRINT addr, int bitPosition);
VOID SimulateFault(INS ins, VOID* v);
VOID BeforeWrite(THREADID threadId, CONTEXT* ctxt, SYSCALL_STANDARD std, void* v);
VOID OnStart(VOID* v);
VOID OnExit(INT32 code, VOID* v);

// Function to flip a specific bit in the address
ADDRINT FlipBit(ADDRINT addr, int bitPosition) {
    return addr ^ (1ULL << bitPosition);
}

// Function to simulate fault by flipping bits in the return address
VOID SimulateFault(INS ins, VOID* v) {
    if (INS_IsRet(ins)) {
        // print the current instruction to logfile
        string ins_str = INS_Disassemble(ins);
        logFile << ins_str << std::endl;
        // print the address of the next instruction to logfile
        logFile << "Next address: 0x" << std::hex << INS_NextAddress(ins) << std::endl;


        ADDRINT returnAddr = INS_NextAddress(ins);

        // If we haven't seen this address before, start with bit 0
        if (addressBitFlips.find(returnAddr) == addressBitFlips.end()) {
            addressBitFlips[returnAddr] = 0;
        }

        int currentBitFlip = addressBitFlips[returnAddr];
        ADDRINT newAddr = FlipBit(returnAddr, currentBitFlip);

        logFile << std::hex << "Original return address: 0x" << returnAddr 
                << ", New return address: 0x" << newAddr 
                << ", Bit flipped: " << std::dec << currentBitFlip << std::endl;

        // Insert a direct jump to the new address
        INS_InsertDirectJump(ins, IPOINT_BEFORE, newAddr);

        // Move to next bit for the next time we see this address
        addressBitFlips[returnAddr] = (currentBitFlip + 1) % MAX_BIT_FLIP;
    }
}

// This function is called before every write() system call.
VOID BeforeWrite(THREADID threadId, CONTEXT* ctxt, SYSCALL_STANDARD std, void* v) {
    ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
    const char* buf = (const char*)PIN_GetSyscallArgument(ctxt, std, 1);
    ADDRINT size = PIN_GetSyscallArgument(ctxt, std, 2);
    if (fd == STDOUT_FILENO && redirectedFD != -1) {
        // Redirect stdout writes to the file.
        write(redirectedFD, buf, size);
    }
}

// This function is called when the instrumented application starts.
VOID OnStart(VOID* v) {
    // Open our output file.
    redirectedFD = open(outputFile, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (redirectedFD == -1) {
        std::cerr << "Failed to open " << outputFile << std::endl;
        exit(1);
    }
}

// This function is called when the instrumented application exits.
VOID OnExit(INT32 code, VOID* v) {
    if (redirectedFD != -1) {
        close(redirectedFD);
    }
    fprintf(trace, "#eof\n");
    fclose(trace);
    logFile.close();
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v) {
    // Get the instruction string
    string ins_str = INS_Disassemble(ins);
    BOOL isCallInstruction = INS_IsCall(ins);
    ADDRINT returnAddr = 0;

    // Determine the return address if it is a call instruction
    if (isCallInstruction) {
        returnAddr = INS_NextAddress(ins);
    }

    // Check if we are dealing with a call instruction and print accordingly
    if (isCallInstruction) {
        fprintf(trace, "%p: %s, Return Address: %p\n", (void*)INS_Address(ins), ins_str.c_str(), (void*)returnAddr);
    } else {
        fprintf(trace, "%p: %s\n", (void*)INS_Address(ins), ins_str.c_str());
    }

    // Simulate fault for return instructions
    SimulateFault(ins, v);
}

// Main function
int main(int argc, char* argv[]) {
    // Initialize pin
    if (PIN_Init(argc, argv)) return -1;

    trace = fopen("itrace.out", "w");
    if (!trace) {
        std::cerr << "Failed to open itrace.out" << std::endl;
        return -1;
    }

    // Open log file for fault simulation
    logFile.open("fault_simulation.log");
    if (!logFile.is_open()) {
        std::cerr << "Failed to open fault_simulation.log" << std::endl;
        return -1;
    }

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register a function to be called before the write() system call.
    PIN_AddSyscallEntryFunction(BeforeWrite, NULL);

    // Register our start and exit functions.
    PIN_AddApplicationStartFunction(OnStart, nullptr);
    PIN_AddFiniFunction(OnExit, nullptr);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}