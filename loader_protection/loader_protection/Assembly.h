#pragma once
#include "win_includes.h"


namespace asm_instructions
{
	class Asm
	{
	public:


		bool INT3_Scan()
		{
			__try
			{
				__asm int 3;
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return false;
			}
		}


		bool INT2D()
		{
			__try
			{
				__asm
				{
					xor eax, eax;  
					int 0x2D;      
					nop;           
				}
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return false;
			}
		}



		bool Prefix()
		{
			__try
			{
				__asm __emit 0xF3
				__asm __emit 0x64
				__asm __emit 0xF1
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return false;
			}
		}



		bool Trace()
		{
			__try
			{
				__asm
				{
					pushfd
					mov dword ptr[esp], 0x100
					popfd
					nop
				}
				return true;
			}
			__except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
				? EXCEPTION_EXECUTE_HANDLER
				: EXCEPTION_CONTINUE_EXECUTION)
			{
				return false;
			}
		}


		bool g_bDebugged = false;

		int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
		{
			g_bDebugged = code != EXCEPTION_BREAKPOINT;
			return EXCEPTION_EXECUTE_HANDLER;
		}

		bool Check_filter()
		{
			__try
			{
				__asm __emit(0xCD);
				__asm __emit(0x03);
			}
			__except (filter(GetExceptionCode(), GetExceptionInformation()))
			{
				return g_bDebugged;
			}
		}


		bool IsTraced()
		{
			__asm
			{
				push 3
				pop  gs

				__asm SeclectorsLbl:
				mov  ax, gs
					cmp  al, 3
					je   SeclectorsLbl

					push 3
					pop  gs
					mov  ax, gs
					cmp  al, 3
					jne  Selectors_Debugged
			}

			return false;

		Selectors_Debugged:
			return true;
		}

	};
}


asm_instructions::Asm* asm_protect;