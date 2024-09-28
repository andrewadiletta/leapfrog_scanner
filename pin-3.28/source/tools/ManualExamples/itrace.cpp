#include <stdio.h>
#include <string>
#include "pin.H"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>

using std::string;
FILE* trace;
// Name of the file where stdout will be redirected.
const char *outputFile = "stdout_redirect.txt";

// This is the file descriptor for our output file.
int redirectedFD = -1;

// This function is called before every write() system call.
VOID BeforeWrite(THREADID threadId, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v) {
    ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
    const char *buf = (const char *)PIN_GetSyscallArgument(ctxt, std, 1);
    ADDRINT size = PIN_GetSyscallArgument(ctxt, std, 2);

    if (fd == STDOUT_FILENO && redirectedFD != -1) {
        // Redirect stdout writes to the file.
        write(redirectedFD, buf, size);
    }
    
}

// This function is called when the instrumented application starts.
VOID OnStart(VOID *v) {
    // Open our output file.
    redirectedFD = open(outputFile, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (redirectedFD == -1) {
        std::cerr << "Failed to open " << outputFile << std::endl;
        exit(1);
    }
}

// This function is called when the instrumented application exits.
VOID OnExit(INT32 code, VOID *v) {
    if (redirectedFD != -1) {
        close(redirectedFD);
    }
    fprintf(trace, "#eof\n");
    fclose(trace);
}


// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{
    // Get the instruction string, skip the space at the beginning
    string ins_str = INS_Disassemble(ins);
    BOOL isCallInstruction = INS_IsCall(ins);
    ADDRINT returnAddr = 0;

    // Determine the return address if it is a call instruction
    if (isCallInstruction) {
        returnAddr = INS_Address(ins) + INS_Size(ins);
    }

    // Check if we are dealing with a call instruction and print accordingly
    if (isCallInstruction) {
        fprintf(trace, "%p: %s, Return Address: %p\n", (void*)INS_Address(ins), ins_str.c_str(), (void*)returnAddr);
    } else {
        fprintf(trace, "%p: %s\n", (void*)INS_Address(ins), ins_str.c_str());
    }

}


// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{

}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs and instructions of every instruction executed, and the return address for call instructions\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    trace = fopen("itrace.out", "w");

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

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
