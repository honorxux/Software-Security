#include"PEParser.h"
#include <windows.h>
#include <Commdlg.h>
#include <stdio.h>
#include <Dbghelp.h> 
#include <iostream> 
#include<tlhelp32.h>
#include <tchar.h>
#include <string>

using namespace std;
OPENFILENAME ofn;
DWORD pid;
char *path[];
char szFile[300];
HANDLE hFile;//�ļ����
HANDLE hMapping;//ӳ���ļ����
LPVOID ImageBase;//ӳ���ַ
PIMAGE_DOS_HEADER pDH = nullptr;
PIMAGE_NT_HEADERS pNtH = nullptr;
PIMAGE_FILE_HEADER pfile = nullptr;
PIMAGE_OPTIONAL_HEADER poptional = nullptr;
PIMAGE_SECTION_HEADER pSH = nullptr;
char p[100];
string exename;
TCHAR* moduleName;

HMODULE GetProcessModuleHandle(DWORD pid, TCHAR* moduleName) {	// ���� PID ��ģ��������Ҫд��׺���磺".dll"������ȡģ����ڵ�ַ��
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); //  ��ȡ���̿����а�����th32ProcessID��ָ���Ľ��̵����е�ģ�顣
	if (!handle) {
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}
	do {
		if (_tcscmp(moduleEntry.szModule, moduleName) == 0) {
			return moduleEntry.hModule;
		}
	} while (Module32Next(handle, &moduleEntry));
	CloseHandle(handle);
	return 0;
}

TCHAR*  char2TCAHR(const char* str)

{

	int size = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);

	TCHAR* retStr = new TCHAR[size * sizeof(TCHAR)];

	MultiByteToWideChar(CP_ACP, 0, str, -1, retStr, size);

	return retStr;

}

char* NameOfexe(char* name)  //�Զ���һ��ȡ���ļ���ַ����·���޳������������
{
	string exeName;

	int k = 0;
	for (int i = 0; i < strlen(name); i++)
	{
		if (name[i] == '\\') {
			k = i;
			for (int j = i; j < strlen(name) - i; j++)
			{
				if (name[j] == '\\')
					break;
			}
		}
	}
	int k2 = 0;
	int i = k + 1;
	string names = name;
	for (i; i < strlen(name); i++)
	{
		exeName += name[i];
		k2++;
	}

	for (i = 0; i < exeName.length(); ++i)
	{
		p[i] = exeName[i];
		p[i + 1] = '\0';
	}

	return p;
}
void createit(LPWSTR path) {
	LPWSTR tstr = path;//
	STARTUPINFO si;
	memset(&si, 0, sizeof(STARTUPINFO));//��ʼ��si���ڴ���е�ֵ��
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PROCESS_INFORMATION pi;//�ر��������ý���
	if (!CreateProcess(NULL, tstr,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)) {
		cout << "-------DLL Can't Run!-------------" << endl;
		exit(1);
	}
/*	else {
		cout << "Success!" << endl;
	}
*/
}
bool CloseProcess(unsigned int unProcessID) {//�رս��̺���
	HANDLE bExitCode = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
		| PROCESS_ALL_ACCESS, FALSE, unProcessID);

	if (NULL != bExitCode)
	{

		BOOL bFlag = TerminateProcess(bExitCode, 0);

		CloseHandle(bExitCode);

		return true;

	}
	return false;

}

string TCHAR2STRING(TCHAR* str)
{
	std::string strstr;
	try
	{
		int iLen = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);
		char* chRtn = new char[iLen * sizeof(char)];
		WideCharToMultiByte(CP_ACP, 0, str, -1, chRtn, iLen, NULL, NULL);
		strstr = chRtn;
	}
	catch (std::exception e)
	{
	}
	return strstr;
}



DWORD GetProcessIdFromName(string name)//���ݳ�������ȡ��pid
{
	HANDLE  hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Error!\n");
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	int flag = Process32First(hsnapshot, &pe);

	while (flag)
	{

		if (TCHAR2STRING(pe.szExeFile) == name)
		{
			return pe.th32ProcessID;
		}
		flag = Process32Next(hsnapshot, &pe);
	}

	CloseHandle(hsnapshot);

	return 0;
}



char* ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)//ת��������ת��LPSWSTRΪchar*
{
	LPSTR pszOut = NULL;
	try
	{
		if (lpwszStrIn != NULL)
		{
			int nInputStrLen = wcslen(lpwszStrIn);
			// Double NULL Termination  
			int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, NULL, 0, 0, 0) + 2;
			pszOut = new char[nOutputStrLen];
			if (pszOut)
			{
				memset(pszOut, 0x00, nOutputStrLen);
				WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);
			}
		}
	}
	catch (std::exception e)
	{
	}
	return pszOut;
}


int main() {
	cout << "***********����������ĸѡ���ļ�**************" << endl;
	int a = 0;
	cin >> a;
	cout << "success!!!" << endl;
	IN DWORD o;
	LPVOID* p;
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = (LPWSTR)szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"All\0*.*\0Text\0*.TXT\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&ofn))
	{
		wprintf(L"%s\n\n", ofn.lpstrFile);//��ӡ�ļ�·��
	}
	else
	{
		printf("user cancelled\n");
	}


	ConvertLPWSTRToLPSTR(ofn.lpstrFile);
	char* path[] = { ConvertLPWSTRToLPSTR(ofn.lpstrFile) };
	PE(*path);
	exporttable();
	createit(ofn.lpstrFile);//���г���
	string exename;
	exename = NameOfexe(*path);//
	char *EXENAME = (char*)exename.c_str();
	DWORD pid = GetProcessIdFromName(exename);//���ݽ��̣����ֻ�ȡ��ȡpid
	Getimporttabless(pid);//���
	CloseProcess(pid);//�رս���

	system("pause");
	return 0;
}


void   PE(char* path) { //��ʼ����������ӳ���ļ�



	WCHAR filepath[256];//����ת��
	memset(filepath, 0, sizeof(filepath));
	MultiByteToWideChar(CP_ACP, 0, path, strlen(path) + 1, filepath,
		sizeof(filepath) / sizeof(filepath[0]));

	hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile)
	{
		printf("Can't get hFile \n");
		exit(EXIT_FAILURE);
	}
	//2�������ڴ�ӳ���ļ�����
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, 0);
	if (!hMapping)
	{
		CloseHandle(hFile);
		printf("Can't get hMapping \n");
		exit(EXIT_FAILURE);
	}
	//3�������ڴ�ӳ���ļ�����ͼ
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!ImageBase)
	{
		CloseHandle(hFile);
		CloseHandle(hMapping);
		printf("Can't get ImageBase \n");
		exit(EXIT_FAILURE);
	}
}
bool IsPEFile(LPVOID ImageBase)//�ж��Ƿ�ΪPE
{
	PIMAGE_DOS_HEADER pDH = nullptr;
	PIMAGE_NT_HEADERS pNtH = nullptr;
	if (!ImageBase)//�ж�ӳ���ַ
	{
		return false;
	}

	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)  //�ж��Ƿ�Ϊ"MZ"
	{
		return false;
	}
	//pDH->e_lfanew����PIMAGE_NT_HEADERS32��ƫ�Ƶ�ַ�����ϻ�ַpDH��ΪMAGE_NT_HEADERS�ĵ�ַ
	pNtH = (PIMAGE_NT_HEADERS)(pDH + pDH->e_lfanew);
	return true;
}

void Getimporttabless(DWORD pid) {
	PIMAGE_DOS_HEADER pDH = nullptr;
	PIMAGE_NT_HEADERS pNtH = nullptr;
	PIMAGE_FILE_HEADER pfile = nullptr;
	PIMAGE_OPTIONAL_HEADER poptional = nullptr;
	PIMAGE_SECTION_HEADER pSH = nullptr;
	if (!IsPEFile(ImageBase))
	{
		printf("File is not exe \n");
		exit(EXIT_FAILURE);
	}
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pfile = (PIMAGE_FILE_HEADER)(&pNtH->FileHeader);
	poptional = (PIMAGE_OPTIONAL_HEADER)(&pNtH->OptionalHeader);//��ʼ������

	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = NULL;
	//��ȡ�����
	ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa(
		pNtH,
		ImageBase,
		poptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		NULL);
	//4��ѭ����ӡÿһ��IID����

	while (ImportDirectory->FirstThunk)
	{
		//	(1)��ȡ�����ļ�������
		DWORD ImportNameAdd_RVA = ImportDirectory->Name;
		char* pImportName = (char*)ImageRvaToVa(
			pNtH,
			ImageBase,
			ImportNameAdd_RVA,
			NULL);
		printf("==========Dll Name:%s  ================\n", pImportName);//���ַ���ʽDLLname���
		TCHAR* moduleName = char2TCAHR(pImportName);
		HMODULE hModule = GetProcessModuleHandle(pid, moduleName);//LPCWSTR)pImportName
		printf("VA in system :%08lX \n", (DWORD)hModule);
		printf("OriginalFirstThunk :%08lX \n", ImportDirectory->OriginalFirstThunk);
		printf("TimeDateStamp :%08lX \n", ImportDirectory->TimeDateStamp);
		printf("ForwarderChain:%08lX \n", ImportDirectory->ForwarderChain);
		printf("Name :%08lX \n", ImportDirectory->Name);
		printf("FirstThunk :%08lX \n", ImportDirectory->FirstThunk);
		//�����������ṹ
		//������ţ���ַ��������
		char	cOrd[30], cMemAddr[30], *FuncName;
		//IMAGE_THUNK_DATA��ָ����ȡֵ
		DWORD dwThunk, *pdwThunk = NULL, *pdwRVA = NULL;
		//IMAGE_THUNK_DATA_BY_NAME��ָ��
		PIMAGE_IMPORT_BY_NAME     pByName = NULL;
		//IID�����е�FirstThunk��32λȡֵ
		dwThunk = ImportDirectory->FirstThunk;
		pdwRVA = (DWORD*)dwThunk;
		//IMAGE_THUNK_DATA��VA		
		pdwThunk = (DWORD*)ImageRvaToVa(pNtH, ImageBase, dwThunk, NULL);
		if (!pdwThunk)//IAT
			//return 0;
		//ѭ����ӡIAT�������
			while (*pdwThunk) ////IMAGE_THUNK_DATA��VA	
			{

				//ָ��IAT���飨IMAGE_THUNK_DATA����RVA
				printf("IMAGE_THUNK_DATA��RVA��%08lX \n", (DWORD)pdwRVA);
				//IAT���飨IMAGE_THUNK_DATA����VA
				printf("IMAGE_THUNK_DATA��VA��%08lX \n", (DWORD)(*pdwThunk));
				//�ж�ThunkValue���λ��ȡֵ��0����1
				if (HIWORD(*pdwThunk) == 0x8000)
				{	//����ţ���������		

					//cOrd[30] = IMAGE_ORDINAL32(*pdwThunk);
					//FuncName = (char*)cOrd;
					printf("Name :0x%08lX    \n", IMAGE_ORDINAL32(*pdwThunk));
				}
				else
				{	//�Ǻ����������������
					pByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNtH, ImageBase, (DWORD)(*pdwThunk), NULL);
					if (pByName)
					{
						printf("Hint: %04lX  ", pByName->Hint);
						FuncName = (char*)pByName->Name;
						printf("FuncName=%s    \n", FuncName);
					}//end if
					else
					{	//������źͺ�������
						printf("MemAddr: %08lX  ", (DWORD)(*pdwThunk));
						FuncName = (char*)(*pdwThunk);
						printf("FuncName=0x%x    \n", FuncName);
					}//end else
				}
				//ѭ��������һ�����������
				++pdwRVA;
				++pdwThunk;
			}//end else
		ImportDirectory++;
	}//end while
}

void exporttable() {
	DWORD dwDataStartRVA;//������RVA
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL; //ָ��������ָ��
	PIMAGE_DOS_HEADER pDH = nullptr;
	PIMAGE_NT_HEADERS pNtH = nullptr;
	PIMAGE_OPTIONAL_HEADER poptional = nullptr;

	if (!IsPEFile(ImageBase))
	{
		printf("File is not exe \n");
		exit(EXIT_FAILURE);
	}
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	poptional = (PIMAGE_OPTIONAL_HEADER)(&pNtH->OptionalHeader);//��ʼ������

	//������RVA
	dwDataStartRVA = poptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//������VA
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);
	if (!pExportDir)
	{
		printf("Don't have Export Directory\n");
	}
	else {
		//����IED�ṹ
		printf("\n-------------Export Table-------------------\n");
		printf("Characteristics =0x%s  \n", pExportDir->Characteristics);
		printf("TimeDateStamp =%08lX\n", pExportDir->TimeDateStamp);
		printf("MajorVersion =%04lX\n", pExportDir->MajorVersion);
		printf("MinorVersion =%04lX\n", pExportDir->MinorVersion);
		printf("Name = %08lX\n", pExportDir->Name);
		printf("Base = %08lX\n", pExportDir->Base);
		printf("NumberOfFunctions = %08lX\n", pExportDir->NumberOfFunctions);
		printf("NumberOfNames = %08lX\n", pExportDir->NumberOfNames);
		printf("AddressOfFunctions = %08lX\n", pExportDir->AddressOfFunctions);
		printf("AddressOfNames = %08lX\n", pExportDir->AddressOfNames);
		printf("AddressOfNameOrdinals = %08lX\n", pExportDir->AddressOfNameOrdinals);

		//����ģ���name
		char* DllName;	//ģ������ָ��
		DllName = (char*)ImageRvaToVa(pNtH, ImageBase, pExportDir->Name, NULL);
		printf("Dll Name:%s  \n", DllName);//���ַ���ʽ���Dll Name

		//����3����Ҫʹ�õı���
		UINT		iNumOfName = 0;	// NumberOfNames		
		PDWORD	pdwRvas;		// AddressOfFunctions		EAT����
		PDWORD	pdwNames;		// AddressOfNames			ENT����
		PWORD	pwOrds;			// AddressOfNameOrdinals	EOT����
		DWORD 	funNum; 		//�������
		char* funName;			//������
		UINT		i = 0, j = 0, k = 0;

		//ENT�����VA��ַ
		dwDataStartRVA = pExportDir->AddressOfNames;
		pdwNames = (PDWORD)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);

		//EOT�����VA��ַ
		dwDataStartRVA = pExportDir->AddressOfNameOrdinals;
		pwOrds = (PWORD)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);

		//EAT�����VA��ַ
		dwDataStartRVA = pExportDir->AddressOfFunctions;
		pdwRvas = (PDWORD)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);

		//name��Ŀ
		iNumOfName = pExportDir->NumberOfNames;

		//�����������ŵ���Ϣ
		for (i = 0; i < pExportDir->NumberOfFunctions; i++)	//����ȡEAT���е�����
		{
			if (*pdwRvas)	//EAT��ǿ�
			{
				//EAT���е�RVA
				printf("Fun RVA =%08lX\n", (*pdwRvas));

				for (j = 0; j < iNumOfName; j++)//��ǰRVA��EAT�е��±��Ƿ���EOT���У�
				{
					if (i == pwOrds[j])//����ڣ����ַ�ʽ����
					{
						funName = (char*)ImageRvaToVa(pNtH, ImageBase, pdwNames[j], NULL);
						printf("Function Name:%s  \n", funName);
						break;
					}//end if
				//������ŷ�ʽ����
					funNum = (DWORD)(pExportDir->Base + i);
					printf("Base = %08lX\n", (pExportDir->Base + i));

				}//end for
				++pdwRvas;		  //EAT������һ������
			}//end if
		}
	}
}




