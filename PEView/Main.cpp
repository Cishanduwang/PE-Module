/*
	Time:2020/5/31
	Author:Lara Lee
*/
#include <iostream>
#include <Windows.h>
#include <tchar.h>
#define DEBUG
using namespace std;

int main(int argc, char* argv[]) 
{
	//Load Library
	typedef PIMAGE_DOS_HEADER (*PFUNGetDosHeader)(LPVOID);
	typedef PIMAGE_NT_HEADERS (*PFUNGetNtHeader)(LPVOID);
	typedef PIMAGE_OPTIONAL_HEADER (*PFUNGetOptionalHeader)(LPVOID);
	typedef PIMAGE_SECTION_HEADER (*PFUNGetSectionHeader)(LPVOID);
	typedef BOOL (*PFUNVerifyDosHeader)(LPVOID);
	typedef BOOL (*PFUNVerifyNtHeader)(LPVOID);
	typedef PIMAGE_FILE_HEADER (*PFUNGetFileHeader)(LPVOID);

	HMODULE hMod = LoadLibrary(_T("PE.dll"));
	if (hMod == NULL)
	{
		MessageBox(NULL, _T("DLL 加载失败"), _T("错误"), MB_OK);
		return -1;
	}

	PFUNGetDosHeader GetDosHedaer = (PFUNGetDosHeader)GetProcAddress(hMod, "GetDosHeader");
	PFUNGetNtHeader GetNtHedaer = (PFUNGetNtHeader)GetProcAddress(hMod, "GetNtHeader");
	PFUNGetOptionalHeader GetOptionalHeader = (PFUNGetOptionalHeader)GetProcAddress(hMod, "GetOptionalHeader");
	PFUNGetSectionHeader GetSectionHeader = (PFUNGetSectionHeader)GetProcAddress(hMod, "GetSectionHeader");
	PFUNVerifyDosHeader VerifyDosHeader = (PFUNVerifyDosHeader)GetProcAddress(hMod, "VerifyDosHeader");
	PFUNVerifyNtHeader VerifyNtHeader = (PFUNVerifyNtHeader)GetProcAddress(hMod, "VerifyNtHeader");
	PFUNGetFileHeader GetFileHeader = (PFUNGetFileHeader)GetProcAddress(hMod, "GetFileHeader");

	wcout.imbue(locale("chs"));//使wcout可以输出中文
	TCHAR filePath[MAX_PATH];
	MultiByteToWideChar(CP_ACP, NULL, argv[1], strlen(argv[1]) + 1, filePath, MAX_PATH);
#ifdef DEBUG
	wcout << _T("[D]FilePath is: ") << filePath << endl;
#endif // DEBUG
	if (!filePath)
	{
		wcout << _T("[E]FilePath cant not be null.") << endl;
		return -1;
	}
	HANDLE hFile = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wcout << _T("[E]Can not open file.") << endl;
		return -1;
	}
	HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE | SEC_IMAGE, 0, 0, 0);
	if (hMap == NULL)
	{
		CloseHandle(hFile);
		wcout << _T("[E]Can not map file.") << endl;
		return -1;
	}
	LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_READ | FILE_SHARE_WRITE, 0, 0, 0); //将磁盘文件映射到内存中
	if (lpBase == NULL)
	{
		CloseHandle(hMap);
		CloseHandle(hFile);
		wcout << _T("[E]Can not map view of file.") << endl;
		return -1;
	}
	PIMAGE_DOS_HEADER hDosHeader = GetDosHedaer(lpBase);
	if (!VerifyDosHeader(lpBase))
	{
		CloseHandle(hMap);
		CloseHandle(hFile);
		wcout << _T("[E]This is net a PE file.") << endl;
		return -1;
	}
	PIMAGE_NT_HEADERS hNtHeader = GetNtHedaer(lpBase);
	PIMAGE_FILE_HEADER hFileHeader = GetFileHeader(lpBase);
	PIMAGE_OPTIONAL_HEADER hOptionalHeader = GetOptionalHeader(lpBase);
	PIMAGE_SECTION_HEADER hSectionHeader = GetSectionHeader(lpBase);
	
	wcout << _T("入口地址：") << hex << showbase << hOptionalHeader->AddressOfEntryPoint << endl;
	wcout << _T("映象基地址：") << hex << showbase << hOptionalHeader->ImageBase << endl;

	//收尾清理
	UnmapViewOfFile(lpBase);
	CloseHandle(hMap);
	CloseHandle(hFile);
	system("pause");
	return 0;
}