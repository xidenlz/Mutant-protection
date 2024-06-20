#include "win_includes.h"
#include "local_includes.h"
#pragma intrinsic(_ReturnAddress)






/*
MIT License

https://github.com/Mes2d

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






namespace checks
{
	class Checks
	{
	public:
		bool Functions_Table()
		{

			/* Add your important functions to the table */
			PVOID functionsToCheck[] = {
			&our_secret_functions::do_something1,
			&our_secret_functions::do_something2,
			&our_secret_functions::do_something3,
			};
			for (auto funcAddr : functionsToCheck)
			{
				/* When skids reversing the program it will through false-positive functions AKA currpted DATA*/
				if (dbg->IsDissasambled(0xCC, funcAddr))
					return true;
			}
			return false;
		}

		/****************************************************************************************/
		/****************************************************************************************/
		/****************************************************************************************/


		/* Check for nop bytes (Fill with) skids using this method with keyauth apps to get unauthorized access */
		void Byte_Scan()
		{
			PVOID pRetAddress = _ReturnAddress();
			if (*(PBYTE)pRetAddress == 0xCC) // int 3
			{
				DWORD dwOldProtect;
				if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
				{
					*(PBYTE)pRetAddress = 0x90; // nop
					VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
				}
			}
		}




	};
}

checks::Checks* g_check;

namespace our_secret_functions
{
	void do_something1()
	{

	}
	void do_something2()
	{

	}
	void do_something3()
	{

	}
}








/* Start Protection */
void StartProtection()
{
	/* Memory */
	bool mem_thread = m_protect->kernel_mem_share();
	if (mem_thread)
	{
		printf("Memory thread started\n");
	}


	/* Checks */
	bool checks_thread = g_check->Functions_Table();
	if (checks_thread)
	{
		printf("Checks thread started\n");
	}


	/* Assembly */
	asm_protect->INT2D();
	asm_protect->INT3_Scan();
	asm_protect->Prefix();
	asm_protect->IsTraced();
	asm_protect->Trace();
	asm_protect->Check_filter();

	Sleep(1000);


	dbg->IsDebuggerPresent();
	dbg->IsHWBP();
	dbg->ntdll_patch();
	dbg->NtGlobalFlag();
	dbg->NtQuerySystemInfo();
	dbg->ProcessDebugObjectHandle();

	/*
	 * Not only will this break their PC, but it will also thwart their efforts each time they try to debug or reverse engineer the program.
	 */

	
}




int main()
{
	StartProtection();
}