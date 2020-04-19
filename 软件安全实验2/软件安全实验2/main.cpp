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
HANDLE hFile;//文件句柄
HANDLE hMapping;//映射文件句柄
LPVOID ImageBase;//映像基址
PIMAGE_DOS_HEADER pDH = nullptr;
PIMAGE_NT_HEADERS pNtH = nullptr;
PIMAGE_FILE_HEADER pfile = nullptr;
PIMAGE_OPTIONAL_HEADER poptional = nullptr;
PIMAGE_SECTION_HEADER pSH = nullptr;
char p[100];
string exename;
TCHAR* moduleName;

HMODULE GetProcessModuleHandle(DWORD pid, TCHAR* moduleName) {	// 根据 PID 、模块名（需要写后缀，如：".dll"），获取模块入口地址。
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
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

char* NameOfexe(char* name)  //自定义一个取出文件地址绝对路径剔除多余参数函数
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
	memset(&si, 0, sizeof(STARTUPINFO));//初始化si在内存块中的值（
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PROCESS_INFORMATION pi;//必备参数设置结束
	if (!CreateProcess(NULL, tstr,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)) {
		cout << "-------DLL Can't Run!-------------" << endl;
		exit(1);
	}
/*	else {
		cout << "Success!" << endl;
	}
*/
}
bool CloseProcess(unsigned int unProcessID) {//关闭进程函数
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



DWORD GetProcessIdFromName(string name)//根据程序名获取到pid
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



char* ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)//转换函数，转换LPSWSTR为char*
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
	cout << "***********输入任意字母选择文件**************" << endl;
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
		wprintf(L"%s\n\n", ofn.lpstrFile);//打印文件路径
	}
	else
	{
		printf("user cancelled\n");
	}


	ConvertLPWSTRToLPSTR(ofn.lpstrFile);
	char* path[] = { ConvertLPWSTRToLPSTR(ofn.lpstrFile) };
	PE(*path);
	exporttable();
	createit(ofn.lpstrFile);//运行程序
	string exename;
	exename = NameOfexe(*path);//
	char *EXENAME = (char*)exename.c_str();
	DWORD pid = GetProcessIdFromName(exename);//根据进程，名字获取获取pid
	Getimporttabless(pid);//输出
	CloseProcess(pid);//关闭进程

	system("pause");
	return 0;
}


void   PE(char* path) { //初始化函数创建映射文件



	WCHAR filepath[256];//类型转换
	memset(filepath, 0, sizeof(filepath));
	MultiByteToWideChar(CP_ACP, 0, path, strlen(path) + 1, filepath,
		sizeof(filepath) / sizeof(filepath[0]));

	hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile)
	{
		printf("Can't get hFile \n");
		exit(EXIT_FAILURE);
	}
	//2、创建内存映射文件对象
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, 0);
	if (!hMapping)
	{
		CloseHandle(hFile);
		printf("Can't get hMapping \n");
		exit(EXIT_FAILURE);
	}
	//3、创建内存映射文件的视图
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!ImageBase)
	{
		CloseHandle(hFile);
		CloseHandle(hMapping);
		printf("Can't get ImageBase \n");
		exit(EXIT_FAILURE);
	}
}
bool IsPEFile(LPVOID ImageBase)//判断是否为PE
{
	PIMAGE_DOS_HEADER pDH = nullptr;
	PIMAGE_NT_HEADERS pNtH = nullptr;
	if (!ImageBase)//判断映像基址
	{
		return false;
	}

	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)  //判断是否为"MZ"
	{
		return false;
	}
	//pDH->e_lfanew保存PIMAGE_NT_HEADERS32的偏移地址，加上基址pDH即为MAGE_NT_HEADERS的地址
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
	poptional = (PIMAGE_OPTIONAL_HEADER)(&pNtH->OptionalHeader);//初始化部分

	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = NULL;
	//获取导入表
	ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa(
		pNtH,
		ImageBase,
		poptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		NULL);
	//4、循环打印每一个IID数组

	while (ImportDirectory->FirstThunk)
	{
		//	(1)获取导入文件的名字
		DWORD ImportNameAdd_RVA = ImportDirectory->Name;
		char* pImportName = (char*)ImageRvaToVa(
			pNtH,
			ImageBase,
			ImportNameAdd_RVA,
			NULL);
		printf("==========Dll Name:%s  ================\n", pImportName);//以字符方式DLLname输出
		TCHAR* moduleName = char2TCAHR(pImportName);
		HMODULE hModule = GetProcessModuleHandle(pid, moduleName);//LPCWSTR)pImportName
		printf("VA in system :%08lX \n", (DWORD)hModule);
		printf("OriginalFirstThunk :%08lX \n", ImportDirectory->OriginalFirstThunk);
		printf("TimeDateStamp :%08lX \n", ImportDirectory->TimeDateStamp);
		printf("ForwarderChain:%08lX \n", ImportDirectory->ForwarderChain);
		printf("Name :%08lX \n", ImportDirectory->Name);
		printf("FirstThunk :%08lX \n", ImportDirectory->FirstThunk);
		//这里输出五个结构
		//函数序号，地址，函数名
		char	cOrd[30], cMemAddr[30], *FuncName;
		//IMAGE_THUNK_DATA的指针与取值
		DWORD dwThunk, *pdwThunk = NULL, *pdwRVA = NULL;
		//IMAGE_THUNK_DATA_BY_NAME的指针
		PIMAGE_IMPORT_BY_NAME     pByName = NULL;
		//IID数组中的FirstThunk，32位取值
		dwThunk = ImportDirectory->FirstThunk;
		pdwRVA = (DWORD*)dwThunk;
		//IMAGE_THUNK_DATA的VA		
		pdwThunk = (DWORD*)ImageRvaToVa(pNtH, ImageBase, dwThunk, NULL);
		if (!pdwThunk)//IAT
			//return 0;
		//循环打印IAT表的内容
			while (*pdwThunk) ////IMAGE_THUNK_DATA的VA	
			{

				//指向IAT数组（IMAGE_THUNK_DATA）的RVA
				printf("IMAGE_THUNK_DATA的RVA：%08lX \n", (DWORD)pdwRVA);
				//IAT数组（IMAGE_THUNK_DATA）的VA
				printf("IMAGE_THUNK_DATA的VA：%08lX \n", (DWORD)(*pdwThunk));
				//判断ThunkValue最高位的取值是0还是1
				if (HIWORD(*pdwThunk) == 0x8000)
				{	//是序号，则输出序号		

					//cOrd[30] = IMAGE_ORDINAL32(*pdwThunk);
					//FuncName = (char*)cOrd;
					printf("Name :0x%08lX    \n", IMAGE_ORDINAL32(*pdwThunk));
				}
				else
				{	//是函数名，输出函数名
					pByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNtH, ImageBase, (DWORD)(*pdwThunk), NULL);
					if (pByName)
					{
						printf("Hint: %04lX  ", pByName->Hint);
						FuncName = (char*)pByName->Name;
						printf("FuncName=%s    \n", FuncName);
					}//end if
					else
					{	//不是序号和函数名，
						printf("MemAddr: %08lX  ", (DWORD)(*pdwThunk));
						FuncName = (char*)(*pdwThunk);
						printf("FuncName=0x%x    \n", FuncName);
					}//end else
				}
				//循环处理下一个函数的情况
				++pdwRVA;
				++pdwThunk;
			}//end else
		ImportDirectory++;
	}//end while
}

void exporttable() {
	DWORD dwDataStartRVA;//输出表的RVA
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL; //指向输出表的指针
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
	poptional = (PIMAGE_OPTIONAL_HEADER)(&pNtH->OptionalHeader);//初始化部分

	//输出表的RVA
	dwDataStartRVA = poptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//输出表的VA
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);
	if (!pExportDir)
	{
		printf("Don't have Export Directory\n");
	}
	else {
		//分析IED结构
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

		//分析模块的name
		char* DllName;	//模块名字指针
		DllName = (char*)ImageRvaToVa(pNtH, ImageBase, pExportDir->Name, NULL);
		printf("Dll Name:%s  \n", DllName);//以字符方式输出Dll Name

		//分析3个表要使用的变量
		UINT		iNumOfName = 0;	// NumberOfNames		
		PDWORD	pdwRvas;		// AddressOfFunctions		EAT数组
		PDWORD	pdwNames;		// AddressOfNames			ENT数组
		PWORD	pwOrds;			// AddressOfNameOrdinals	EOT数组
		DWORD 	funNum; 		//函数序号
		char* funName;			//函数名
		UINT		i = 0, j = 0, k = 0;

		//ENT数组的VA地址
		dwDataStartRVA = pExportDir->AddressOfNames;
		pdwNames = (PDWORD)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);

		//EOT数组的VA地址
		dwDataStartRVA = pExportDir->AddressOfNameOrdinals;
		pwOrds = (PWORD)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);

		//EAT数组的VA地址
		dwDataStartRVA = pExportDir->AddressOfFunctions;
		pdwRvas = (PDWORD)ImageRvaToVa(pNtH, ImageBase, dwDataStartRVA, NULL);

		//name数目
		iNumOfName = pExportDir->NumberOfNames;

		//分析导出符号的信息
		for (i = 0; i < pExportDir->NumberOfFunctions; i++)	//依次取EAT表中的数据
		{
			if (*pdwRvas)	//EAT表非空
			{
				//EAT表中的RVA
				printf("Fun RVA =%08lX\n", (*pdwRvas));

				for (j = 0; j < iNumOfName; j++)//当前RVA在EAT中的下标是否在EOT表中？
				{
					if (i == pwOrds[j])//如果在，名字方式导出
					{
						funName = (char*)ImageRvaToVa(pNtH, ImageBase, pdwNames[j], NULL);
						printf("Function Name:%s  \n", funName);
						break;
					}//end if
				//否则序号方式导出
					funNum = (DWORD)(pExportDir->Base + i);
					printf("Base = %08lX\n", (pExportDir->Base + i));

				}//end for
				++pdwRvas;		  //EAT表中下一个数据
			}//end if
		}
	}
}




