
#include <Windows.h>
#include <iostream>

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
    DWORD sectionTableAddress;
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

int main()
{
    std::cout << "Hello World!\n";
}