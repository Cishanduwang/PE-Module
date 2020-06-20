#ifdef PE_EXPORTS
#define PE_API extern "C" __declspec(dllexport)
#else
#define PE_API extern "C" __declspec(dllimport)
#endif

///----------/
///DOS_HEDAER/
///----------/     /-----------/
///NT_HEDAER /-----/SIGNATURE  /
///----------/     /-----------/
///SECTION_HEADER/ /FILE_HEADER/
///----------/     /-----------/
///                /OPTINAL_HEADER/
///	               /-----------/
	            

PE_API PIMAGE_DOS_HEADER GetDosHeader(LPVOID lpFile);
PE_API PIMAGE_NT_HEADERS GetNtHeader(LPVOID lpFile);
PE_API PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPVOID lpFile);
PE_API PIMAGE_SECTION_HEADER GetSectionHeader(LPVOID lpFile);
PE_API PIMAGE_FILE_HEADER GetFileHeader(LPVOID lpFile);
PE_API BOOL VerifyDosHeader(LPVOID lpFile);
PE_API BOOL VerifyNtHeader(LPVOID lpFile);
