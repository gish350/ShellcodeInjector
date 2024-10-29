
#include <Windows.h>
#include <iostream>
#include <string>
using namespace std;

BOOL checkDosHeader(BYTE* buffer)
{
    if (*buffer == 'M' && *(buffer + 1) == 'Z')
        return TRUE;
    return FALSE;
}

BOOL checkNtHeaders(IMAGE_NT_HEADERS* nt, DWORD* out_nSection, IMAGE_SECTION_HEADER* out_sectionTableAddress)
{
    out_sectionTableAddress = (IMAGE_SECTION_HEADER*)(nt->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
    *out_nSection = nt->FileHeader.NumberOfSections;
    return TRUE;
}

BOOL getShParameters(BYTE* buffer, DWORD* offset, DWORD* size)
{
    BOOL ok;
    DWORD nSections;
    DWORD index;
    DWORD sectionTableAddress = 0;
    IMAGE_SECTION_HEADER* sectionHeader;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
   

    ok = checkDosHeader(buffer);
    if (!ok)
    {
        printf("[getShCodeParameters]: Header check failed\n");
        return FALSE;
    }
    ok = checkNtHeaders(nt, &nSections, (IMAGE_SECTION_HEADER*)sectionTableAddress);
    if (!ok)
    {
        printf("[getShCodeParamters]: NT Header check failed\n");
        return(FALSE);
    }

    // iterate through section header
    sectionHeader = (IMAGE_SECTION_HEADER*)sectionTableAddress;
    for (index = 0; index < nSections; index++)
    {
        printf("[getShCodeParameters]: section %d\n", index);
        if
        (
            sectionHeader[index].Name[0]==  '.' &&
            sectionHeader[index].Name[1] == 'c' &&
            sectionHeader[index].Name[2] == 'o' &&
            sectionHeader[index].Name[3] == 'd' &&
            sectionHeader[index].Name[4] == 'e'
        )
        {
            printf("[getShCodeParameters]: found: .code\n");
            *offset = sectionHeader[index].PointerToRawData;
            *size = sectionHeader[index].SizeOfRawData;
            printf("[getShCodeParameters]: call success\n");
            return TRUE;
        }
    }
    printf("[getShCodeParameters]: Couldn't find .code section\n");
    return FALSE;
}

DWORD rva2raw(DWORD numOfSections, IMAGE_SECTION_HEADER* FSH, DWORD rva)
{
    for (int i = numOfSections - 1; i >= 0; i--)
        if (FSH[i].VirtualAddress <= rva)
            return FSH[i].PointerToRawData + rva - FSH[i].VirtualAddress;
    return 0xFFFFFFFF;
}

int main()
{
    wstring fileName;
    cout << "Provide path  to PE to extract payload from:\n";
    getline(wcin, fileName);
    HANDLE hFile = CreateFile((fileName.c_str()), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) cout << "Cannot open input file. '\n'";

    DWORD ddFrom = 0;
    DWORD ddTo = 0;
    cout << "address from (hex):\n";
    cin >> hex >> ddFrom;
    cout << "address to (hex):\n";
    cin >> hex >> ddTo;

    cout << "Provide path  to PE to insert payload to:\n";

    HANDLE hFile2 = CreateFile((fileName.c_str()), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile2 == INVALID_HANDLE_VALUE) cout << "Cannot open input file. '\n'";

    DWORD ddFrom2 = 0;
    DWORD ddTo2 = 0;
    cout << "address from (hex):\n";
    cin >> hex >> ddFrom2;
    cout << "address to (hex):\n";
    cin >> hex >> ddTo2;
   
    DWORD tmp;
    DWORD fSize = GetFileSize(hFile, 0);
    BYTE* hInMem = (BYTE*)GlobalAlloc(GMEM_FIXED, fSize);
    if (!hInMem) cout << "Cannot allocate memory. '\n'";
    ReadFile(hFile, hInMem, fSize, &tmp, 0);
    CloseHandle(hFile);

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hInMem + ((IMAGE_DOS_HEADER*)hInMem)->e_lfanew);
    IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)(hInMem + ((IMAGE_DOS_HEADER*)hInMem)->e_lfanew + nt->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
    ddFrom -= nt->OptionalHeader.ImageBase;
    ddTo -= nt->OptionalHeader.ImageBase;

    int ddFromRaw = rva2raw(nt->FileHeader.NumberOfSections, sh, ddFrom);
    if (ddFromRaw == 0xFFFFFFFF) ERROR("Invalid range start.");
    int ddToRaw = ddTo - ddFrom;

    BYTE* temp_test = hInMem + ddFromRaw;


}
