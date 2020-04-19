#include "pch.h"
#include<windows.h>
#include<imageHlp.h>
#include <tchar.h>
#include<CommCtrl.h>

#include <iostream>
using namespace std;

#pragma comment(lib,"imageHlp.lib")
#define GETTHUNK(pImportDesc) ((DWORD)                          \
         ((PIMAGE_IMPORT_DESCRIPTOR)pImportDesc->OriginalFirstThunk ?                      \
         (PIMAGE_IMPORT_DESCRIPTOR)pImportDesc->OriginalFirstThunk:(PIMAGE_IMPORT_DESCRIPTOR)pImportDesc->FirstThunk \
          ))
BOOL WriteDataToFile(LPCSTR Data, LPCWSTR FileName)
{
	HANDLE hFile;
	DWORD dwBytesWritten;
	//char *ch="0x0d0x0a";
   //lstrcat(Data,ch);
	BOOL fSuccess;

	hFile = CreateFile(FileName,   // file name 
		GENERIC_READ | GENERIC_WRITE,    // r_w
		0,  // do not share 
		NULL,// default security 
		OPEN_ALWAYS, // ALWAYS
		FILE_ATTRIBUTE_NORMAL, // normal file 
		NULL);  // no template 
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed with error %d.\n",
			GetLastError());
		return FALSE;
	}

	SetFilePointer(hFile, 3, NULL, FILE_END);

	fSuccess = WriteFile(hFile,
		Data,
		strlen(Data),
		&dwBytesWritten,
		NULL);

	if (!fSuccess)
	{

		printf("WriteFile failed with error %d.\n",
			GetLastError());
		return FALSE;
	}
	else
		CloseHandle(hFile);

	return TRUE;
}
HANDLE ImageBase;
BOOL IsPEFile(LPTSTR lpFilePath)
{
	HANDLE hFile;
	HANDLE hMapping;

	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS  pNTH = NULL;
	hFile = CreateFile(lpFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile) return FALSE;
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapping)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	//Get ImageBase
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!ImageBase)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return FALSE;
	}

	//judge PE File
	if (!ImageBase)
	{
		return FALSE;
	}
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	pNTH = (PIMAGE_NT_HEADERS32)((DWORD)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return TRUE;
}

void ShowDOSHeaderInfo(LPVOID LocalImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	cout << "  e_magic:" << hex << pDH->e_magic << endl;
	cout << "  e_lfarlc:" << hex << pDH->e_lfarlc << endl;
}

void ShowNTHeaderInfo(LPVOID LocalImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	cout << "  Signature:" << hex << pNTH->Signature << endl;
}
void ShowFileHeaderInfo(LPVOID LocalImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pFH = &pNTH->FileHeader;
	cout << "  Machine:" << hex << pFH->Machine << endl;
	cout << "  NumberOfSections:" << hex << pFH->NumberOfSections << endl;
	cout << "  Characteristics:" << hex << pFH->Characteristics << endl;

}
void ShowOptionalHeaderInfo(LPVOID LocalImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pOH = &pNTH->OptionalHeader;
	cout << "  Magic:" << hex << pOH->Magic << endl;
	cout << "  SizeOfCode:" << hex << pOH->SizeOfCode << endl;
	cout << "  AddressOfEntryPoint:" << hex << pOH->AddressOfEntryPoint << endl;
	cout << "  ImageBase:" << hex << pOH->ImageBase << endl;
	cout << "  SectionAlignment:" << hex << pOH->SectionAlignment << endl;
	cout << "  FileAlignment:" << hex << pOH->FileAlignment << endl;
	cout << "  SizeOfImage:" << hex << pOH->SizeOfImage << endl;
}

PIMAGE_SECTION_HEADER GetFirstSectionHeader(LPVOID LocalImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pSH = IMAGE_FIRST_SECTION(pNTH);
	return  pSH;
}
void ShowSectionHeaderInfo(LPVOID LocalImageBase)
{

	WORD                    i;

	PIMAGE_SECTION_HEADER   pSH = NULL;
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pFH = &pNTH->FileHeader;

	if (!pFH)
		return;

	pSH = GetFirstSectionHeader(ImageBase);

	for (i = 0; i < pFH->NumberOfSections; i++)
	{
		cout << "  Section Name:" << pSH->Name << endl;
		cout << "  VirtualAddress:" << hex << pSH->VirtualAddress << endl;
		cout << "  SizeOfRawData:" << hex << pSH->SizeOfRawData << endl;
		cout << "  PointerToRelocations:" << hex << pSH->PointerToRelocations << endl;
		cout << "  NumberOfLinenumbers:" << hex << pSH->NumberOfLinenumbers << endl;
		cout << "  Characteristics:" << hex << pSH->Characteristics << endl;


		++pSH;
	}
}

void ShowRVAInfo(LPVOID LocalImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;
	PIMAGE_SECTION_HEADER   pSH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	pDH = (PIMAGE_DOS_HEADER)LocalImageBase;
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pFH = &pNTH->FileHeader;
	pOH = &pNTH->OptionalHeader;

	if (!pFH)
		return;

	pSH = GetFirstSectionHeader(ImageBase);

	cout << "  _IMAGE_DOS_HEADER:" << hex << (DWORD)pDH - (DWORD)pDH << endl;
	cout << "  _IMAGE_NT_HEADER:" << hex << (DWORD)pNTH - (DWORD)pDH << endl;
	cout << "  _IMAGE_FILE_HEADER:" << hex << (DWORD)pFH - (DWORD)pDH << endl;
	cout << "  _IMAGE_OPTIONAL_HEADER:" << hex << (DWORD)pOH - (DWORD)pDH << endl;
	cout << "  _IMAGE_SECTION_HEADER:" << hex << (DWORD)pSH - (DWORD)pDH << endl;
}

int _tmain(int argc, _TCHAR* argv[])
{
	LPTSTR lpFilePath = argv[1];

	if (argc == 1) cout << "cout :argc=" << argc << "  please scanf file path" << endl;
	else
	{
		if (IsPEFile(lpFilePath))
		{
			cout << "-----------------------it is a PE File------------------------------" << endl;
			cout << "-----------------------ShowRVAInfo(HEX Value)-----------------------" << endl;
			ShowRVAInfo(ImageBase);
			cout << "-----------------------ShowDOSHeaderInfo(HEX Value)-----------------" << endl;
			ShowDOSHeaderInfo(ImageBase);
			cout << "-----------------------ShowNTHeaderInfo(HEX Value)------------------" << endl;
			ShowNTHeaderInfo(ImageBase);
			cout << "-----------------------ShowFileHeaderInfo(HEX Value)-----------------" << endl;
			ShowFileHeaderInfo(ImageBase);
			cout << "-----------------------ShowOptionalHeaderInfo(HEX Value)------------" << endl;
			ShowOptionalHeaderInfo(ImageBase);
			cout << "-----------------------ShowSectionHeaderInfo(HEX Value)-------------" << endl;
			ShowSectionHeaderInfo(ImageBase);
		}
		else
			cout << "it's not a PE File" << endl;

	}

	system("pause");
	return 0;

}
