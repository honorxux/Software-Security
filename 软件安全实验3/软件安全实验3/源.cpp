#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>

#define _WJQ_USED_FLOWER

bool NtGlobalFlag()
{
	__asm
	{
		mov eax,fs:[30h]
		mov eax,[eax+68h]
		and eax,0x70
		test eax,eax
		jne rt_label
		jmp rf_label
	}
rt_label:
	return true;
rf_label:
	return false;
}

void int3AntiDebugger()
{
	__asm
	{
		push se_handler
		push DWORD ptr fs : [0]
		mov DWORD ptr fs : [0], esp

		int 3

		mov eax, 0
		jmp eax



		se_handler :

		mov eax, [esp + 0xc]        //获取context指针
			lea eax, [eax + 0xb8]        //获取context.eip地址
			mov ebx, normal
			mov DWORD ptr[eax], ebx
			xor eax, eax
			ret


			normal :

		pop DWORD ptr fs : [0]
			add esp, 4
	}

}

BOOL IsInDebugger()
{
	HINSTANCE hInst = LoadLibrary(TEXT("kernel32.dll"));
	if (hInst != NULL)
	{
		FARPROC pIsDebuggerPresent = GetProcAddress(hInst, "IsDebuggerPresent");
		if (pIsDebuggerPresent != NULL)
			return pIsDebuggerPresent();
	}
	return FALSE;
}


int main()
{
	IsInDebugger();

	LPCWSTR x1 = TEXT("20171120xxx");

//	int3AntiDebugger();

	MessageBox(NULL, TEXT("vege"), x1, MB_OK);

	NtGlobalFlag();


	return 0;
}