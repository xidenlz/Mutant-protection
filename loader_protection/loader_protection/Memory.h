#include "win_includes.h"


/*
MIT License

Copyright (c) 2024 Musaed

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/



namespace ntdll
{
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
	typedef enum _MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation,
		MemoryWorkingSetList,
	} MEMORY_INFORMATION_CLASS;

	typedef union _PSAPI_WORKING_SET_BLOCK {
		ULONG Flags;
		struct {
			ULONG Protection : 5;
			ULONG ShareCount : 3;
			ULONG Shared : 1;
			ULONG Reserved : 3;
			ULONG VirtualPage : 20;
		};
	} PSAPI_WORKING_SET_BLOCK, * PPSAPI_WORKING_SET_BLOCK;

	typedef struct _MEMORY_WORKING_SET_LIST
	{
		ULONG NumberOfPages;
		PSAPI_WORKING_SET_BLOCK WorkingSetList[1];
	} MEMORY_WORKING_SET_LIST, * PMEMORY_WORKING_SET_LIST;
}





namespace Memory
{
	class memory_protect
	{
	public:
		bool kernel_mem_share()
		{
#ifndef _WIN64
			NTSTATUS status;
			PBYTE pMem = nullptr;
			DWORD dwMemSize = 0;

			do
			{
				dwMemSize += 0x1000;
				pMem = (PBYTE)_malloca(dwMemSize);
				if (!pMem)
					return false;

				memset(pMem, 0, dwMemSize);
				status = ntdll::NtQueryVirtualMemory(
					GetCurrentProcess(),
					NULL,
					ntdll::MemoryWorkingSetList,
					pMem,
					dwMemSize,
					NULL);
			} while (status == STATUS_INFO_LENGTH_MISMATCH);

			ntdll::PMEMORY_WORKING_SET_LIST pWorkingSet = (ntdll::PMEMORY_WORKING_SET_LIST)pMem;
			for (ULONG i = 0; i < pWorkingSet->NumberOfPages; i++)
			{
				DWORD dwAddr = pWorkingSet->WorkingSetList[i].VirtualPage << 0x0C;
				DWORD dwEIP = 0;
				__asm
				{
					push eax
					call $ + 5
					pop eax
					mov dwEIP, eax
					pop eax
				}

				if (dwAddr == (dwEIP & 0xFFFFF000))
					return (pWorkingSet->WorkingSetList[i].Shared == 0) || (pWorkingSet->WorkingSetList[i].ShareCount == 0);
			}
#endif // _WIN64
			return false;
		}


	};
}

Memory::memory_protect* m_protect;


