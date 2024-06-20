#include "win_includes.h"




#pragma pack(push, 1)
struct DbgUiRemoteBreakinPatch
{
	WORD  push_0;
	BYTE  push;
	DWORD CurrentPorcessHandle;
	BYTE  mov_eax;
	DWORD TerminateProcess;
	WORD  call_eax;
};
#pragma pack(pop)



typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN DWORD            ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
	);

enum { SystemKernelDebuggerInformation = 0x23 };

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS;


extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);


typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION;


namespace Debugging
{
	class DbgProtect
	{
	public:
		/* Detect Hardware Breakpoints */
		bool IsHWBP()
		{
			CONTEXT ctx;
			ZeroMemory(&ctx, sizeof(CONTEXT));
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (!GetThreadContext(GetCurrentThread(), &ctx))
				return false;

			return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
		}


		/****************************************************************************************/
		/****************************************************************************************/
		/****************************************************************************************/


		/* Patching DbgUiRemoteBreakin, if the debugger has been attached the loader will crash right away */
		void ntdll_patch()
		{
			HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
			if (!hNtdll)
				return;

			FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
			if (!pDbgUiRemoteBreakin)
				return;

			HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
			if (!hKernel32)
				return;

			FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
			if (!pTerminateProcess)
				return;

			DbgUiRemoteBreakinPatch patch = { 0 };
			patch.push_0 = '\x6A\x00';
			patch.push = '\x68';
			patch.CurrentPorcessHandle = 0xFFFFFFFF;
			patch.mov_eax = '\xB8';
			patch.TerminateProcess = (DWORD)pTerminateProcess;
			patch.call_eax = '\xFF\xD0';

			DWORD dwOldProtect;
			if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
				return;

			::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
				&patch, sizeof(DbgUiRemoteBreakinPatch));
			VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
		}


		/****************************************************************************************/
		/****************************************************************************************/
		/****************************************************************************************/


		/* Simple but effective */
		bool IsDebuggerPresent()
		{
			HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
			if (!hKernel32)
				return false;

			FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
			if (!pIsDebuggerPresent)
				return false;

			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (INVALID_HANDLE_VALUE == hSnapshot)
				return false;

			PROCESSENTRY32W ProcessEntry;
			ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

			if (!Process32FirstW(hSnapshot, &ProcessEntry))
				return false;

			bool bDebuggerPresent = false;
			HANDLE hProcess = NULL;
			DWORD dwFuncBytes = 0;
			const DWORD dwCurrentPID = GetCurrentProcessId();
			do
			{
				__try
				{
					if (dwCurrentPID == ProcessEntry.th32ProcessID)
						continue;

					hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
					if (NULL == hProcess)
						continue;

					if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
						continue;

					if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
					{
						bDebuggerPresent = true;
						break;
					}
				}
				__finally
				{
					if (hProcess)
						CloseHandle(hProcess);
				}
			} while (Process32NextW(hSnapshot, &ProcessEntry));

			if (hSnapshot)
				CloseHandle(hSnapshot);
			return bDebuggerPresent;
		}



		/****************************************************************************************/
		/****************************************************************************************/
		/****************************************************************************************/

		/* When the skids patching or dissasamble our program it will throw false-positive instructions which will destroy the instructions */
		bool IsDissasambled(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
		{
			PBYTE pBytes = (PBYTE)pMemory;
			for (SIZE_T i = 0; ; i++)
			{
				if (((nMemorySize > 0) && (i >= nMemorySize)) ||
					((nMemorySize == 0) && (pBytes[i] == 0xC3)))
					break;

				if (pBytes[i] == cByte)
					return true;
			}
			return false;
		}





		bool ProcessDebugObjectHandle()
		{
			HMODULE hNtdll = LoadLibraryA("ntdll.dll");
			if (hNtdll)
			{
				auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
					hNtdll, "NtQueryInformationProcess");

				if (pfnNtQueryInformationProcess)
				{
					DWORD dwReturned;
					HANDLE hProcessDebugObject = 0;
					const DWORD ProcessDebugObjectHandle = 0x1e;
					NTSTATUS status = pfnNtQueryInformationProcess(
						GetCurrentProcess(),
						ProcessDebugObjectHandle,
						&hProcessDebugObject,
						sizeof(HANDLE),
						&dwReturned);

					if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
						ExitProcess(-1);
				}
			}
		}


		bool NtQuerySystemInfo()
		{
			NTSTATUS status;
			SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;

			status = NtQuerySystemInformation(
				(SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
				&SystemInfo,
				sizeof(SystemInfo),
				NULL);

			return SUCCEEDED(status)
				? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
				: false;
		}


		bool NtGlobalFlag()
		{
#ifndef _WIN64
			PPEB pPeb = (PPEB)__readfsdword(0x30);
			DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#else
			PPEB pPeb = (PPEB)__readgsqword(0x60);
			DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#endif // _WIN64

			if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
				goto being_debugged;

			return false;

		being_debugged:

			return true;
		}

	};
}

Debugging::DbgProtect* dbg;