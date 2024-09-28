#include <stdio.h>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
#include <fcntl.h>

#include "pin.H"
using std::string;
FILE* trace_in;
unsigned long long int source_addr, target_addr;
BOOL source_addr_found = false;
BOOL REDIRECT_ON = true; // Global flag to control redirection
int COUNT = 0;
int SKIP_COUNT = 0;
// Name of the file where stdout will be redirected.
const char *outputFile = "stdout_redirect.txt";

// This is the file descriptor for our output file.
int redirectedFD = -1;

// This function is called before every write() system call.
VOID BeforeWrite(THREADID threadId, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v) {
    ADDRINT fd = PIN_GetSyscallArgument(ctxt, std, 0);
    const char *buf = (const char *)PIN_GetSyscallArgument(ctxt, std, 1);
    ADDRINT size = PIN_GetSyscallArgument(ctxt, std, 2);
    // Check if the write is to stdout.
    if (fd == STDOUT_FILENO && redirectedFD != -1) {
        // Redirect the write to our file.
        write(redirectedFD, buf, size);
        // flush buffer to file
        fsync(redirectedFD);
        // Skip the actual system call to prevent double-writing.
        // PIN_SetSyscallArgument(ctxt, SYSCALL_STANDARD_IA32E_LINUX, 0, (ADDRINT)-1);
    }
    // also make it redirect stderr
    if (fd == STDERR_FILENO && redirectedFD != -1) {
        // Redirect the write to our file.
        write(redirectedFD, buf, size);
        // flush buffer to file
        fsync(redirectedFD);
        // Skip the actual system call to prevent double-writing.
        // PIN_SetSyscallArgument(ctxt, SYSCALL_STANDARD_IA32E_LINUX, 0, (ADDRINT)-1);
    }
}

BOOL OnSignal(THREADID tid, INT32 sig, CONTEXT* ctxt, BOOL hasHandler, 
              const EXCEPTION_INFO* pExceptInfo, void* v)
{
    if (redirectedFD != -1) {
        const char* signame = strsignal(sig);
        std::string excptnameStr = PIN_ExceptionToString(pExceptInfo);
        const char* excptname = excptnameStr.c_str();
        dprintf(redirectedFD, "Received signal %d (%s) due to %s\n", sig, signame ? signame : "unknown", excptname);
    }
    return true; // Terminates the application after the exception
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
        // write the return code of the application to the file as string
        write(redirectedFD, "Return code: ", 13);
        char buf[20];
        snprintf(buf, sizeof(buf), "%d", code);
        write(redirectedFD, buf, strlen(buf));
        write(redirectedFD, "\n", 1);
        close(redirectedFD);
    }
    fclose(trace_in);
    int pid = getpid();
    printf("Process %d exited with code %d\n", pid, code);
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{   
    if( REDIRECT_ON == false) return;
    // Get the instruction string
    string ins_str = INS_Disassemble(ins);
    BOOL isCallInstruction = INS_IsCall(ins);
    ADDRINT returnAddr = 0;
    if (isCallInstruction) {
        returnAddr = INS_Address(ins) + INS_Size(ins);
        if(returnAddr == source_addr){
            fflush(stdout);
            if (COUNT == SKIP_COUNT) {
                source_addr_found = true;
                printf("COUNT = %d\n", COUNT);
                REDIRECT_ON = false;
                printf("*************************************** REDIRECT_ON == false ***************************************\n");
                char buffer[256]; // Buffer for the message
                int len = sprintf(buffer, "\nSource: %llx Target: %llx Count: %d\n", source_addr, target_addr, COUNT); // Format the message
                // redirectedFD = open(outputFile, O_WRONLY | O_CREAT | O_APPEND, 0666);
                if (redirectedFD != -1) {
                    write(redirectedFD, buffer, len); // Write to outputFile
                    fsync(redirectedFD);
                }
                printf("\nSource: %llx Target: %llx\n", source_addr, target_addr);
                fflush(stdout);
                INS_InsertDirectJump(ins, IPOINT_BEFORE, target_addr);
            }
            COUNT++;

        }
    }

    // Insert a call to printip before every other instruction, and pass it the IP, the instruction string, and the stack pointer if it's a call
    // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_PTR, new string(ins_str), IARG_BOOL, isCallInstruction, IARG_ADDRINT, returnAddr, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
 
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
    // get environment variable SKIP_COUNT, default 0
    char* skip_count_char = getenv("SKIP_COUNT");
    if (skip_count_char != NULL) {
        SKIP_COUNT = atoi(skip_count_char);
        if (SKIP_COUNT > 0) {
            printf("Skip count set to %d.\n", SKIP_COUNT);
        }
    }
    else{
        SKIP_COUNT = 0;
        printf("Skip count set to 0.\n");
    }


    // get environment variable TIMEOUT, default 5 seconds
    char* timeout = getenv("SIMULATION_TIMEOUT");
    int timeout_int;
    if (timeout != NULL) {
        timeout_int = atoi(timeout);
        if (timeout_int > 0) {
            printf("Timeout set to %d seconds.\n", timeout_int);
        }
    }else{
        timeout_int = 5;
        printf("Timeout set to 5 seconds.\n");
    }
    // get datadir from environment variable
    trace_in = fopen("itrace.in" , "r");
    if (trace_in == NULL) {
        printf("Error opening the itrace.in file.\n");
        return 1;
    }
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);


    // Register a function to be called before the write() system call.
    PIN_AddSyscallEntryFunction(BeforeWrite, NULL);

    // Register our start and exit functions.
    PIN_AddApplicationStartFunction(OnStart, nullptr);
    PIN_AddFiniFunction(OnExit, nullptr);
    PIN_InterceptSignal(SIGSEGV, OnSignal, 0);  // Intercept segmentation faults as an example
    PIN_InterceptSignal(SIGFPE, OnSignal, 0);   // Intercept arithmetic exceptions as an example


    while (fscanf(trace_in, "%llx %llx", &source_addr, &target_addr) != EOF) {

        // Start the program, never returns
        pid_t child_pid = fork();
        if (child_pid == 0) {
            // run sudo pkill -KILL -f "dummy"
            system("sudo pkill -KILL -f \"dummy\"");
            PIN_StartProgram();
            if (source_addr_found == false)
                printf("Source address not found.\n");
            else
                source_addr_found = false;
            _exit(0); // Exit child process when done
        }
        else {
            fflush(stdout);  // Flush the buffer
            pid_t watcher_pid = fork();
            if (watcher_pid == 0) { // Watcher process
                sleep(timeout_int); // Sleep for 5 seconds
                kill(child_pid, SIGKILL); // Kill the child process
                _exit(0); // Exit watcher process
            } else { // Original parent process
                int status;
                waitpid(child_pid, &status, 0); // Wait for child process to finish
                kill(watcher_pid, SIGKILL); // Kill the watcher process
            }
        }
    }
    return 0;
}
