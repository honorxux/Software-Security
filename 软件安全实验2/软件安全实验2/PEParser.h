#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#pragma comment(lib,"Dbghelp.lib")

bool IsPEFile(LPVOID ImageBase);
void   PE(char* path);
void Getimporttabless(DWORD pid);
void exporttable();