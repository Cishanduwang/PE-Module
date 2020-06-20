#include "stdafx.h"
#include "PE.h"



PE_API PIMAGE_NT_HEADERS GetNtHeader(LPVOID lpFile)
{
	return (PIMAGE_NT_HEADERS)(GetDosHeader(lpFile)->e_lfanew + (DWORD)lpFile);
}

PE_API PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPVOID lpFile)
{
	return &(GetNtHeader(lpFile)->OptionalHeader);
}

PE_API PIMAGE_SECTION_HEADER GetSectionHeader(LPVOID lpFile)
{
	return (PIMAGE_SECTION_HEADER)(GetOptionalHeader(lpFile) + GetNtHeader(lpFile)->FileHeader.SizeOfOptionalHeader);
}

PE_API PIMAGE_FILE_HEADER GetFileHeader(LPVOID lpFile)
{
	return &GetNtHeader(lpFile)->FileHeader;
}

PE_API PIMAGE_DOS_HEADER GetDosHeader(LPVOID lpFile) {
	return (PIMAGE_DOS_HEADER)lpFile;
}

PE_API BOOL VerifyDosHeader(LPVOID lpFile)
{
	return GetDosHeader(lpFile)->e_magic == IMAGE_DOS_SIGNATURE ? TRUE : FALSE;
}

PE_API BOOL VerifyNtHeader(LPVOID lpFile)
{
	return GetNtHeader(lpFile)->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE;
}
