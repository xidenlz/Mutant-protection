#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <Psapi.h>
#include <ntsecapi.h>



#pragma comment(lib, "ntdll.lib")







/* Definitions */
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)



#ifdef _WIN64
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
} PEB, * PPEB;
#else
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;
#endif // _WIN64


