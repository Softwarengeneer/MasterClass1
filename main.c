#include <stdio.h>
#include <stdint.h>
#include <windows.h>

int main() {
    FILE* fileReader = fopen("C:\\Users\\nikit\\Downloads\\winrar-x64-600.exe", "rb");
    if (fileReader == NULL) {
        printf("Невозможно открыть файл C:\\Users\\nikit\\Downloads\\winrar-x64-600.exe");
    } else {
        IMAGE_DOS_HEADER dosHeader;
        fread(&dosHeader, sizeof (IMAGE_DOS_HEADER), 1, fileReader);
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            printf("Неверная сигнатура!");
        } else {

            FILE *text, *bin;
            text = fopen("file.txt", "w");
            bin = fopen("file.bin", "wb");


            IMAGE_NT_HEADERS headers;
            WORD addressEntryPoint = headers.OptionalHeader.AddressOfEntryPoint;
            fseek(fileReader, dosHeader.e_lfanew, SEEK_SET);
            fread(&headers, sizeof(IMAGE_NT_HEADERS), 1, fileReader);            
            fprintf(text, "%s%hu\n", "Address of entry point: ", addressEntryPoint);
            IMAGE_SECTION_HEADER currentSection;
            for (int i = 0; i < headers.FileHeader.NumberOfSections; i++) {
                fread(&currentSection, sizeof(IMAGE_SECTION_HEADER), 1, fileReader);
                fprintf(text, "%s%d\n", "Section", i + 1);
                fprintf(text, "%s%s\n", "Name: ", currentSection.Name);
                fprintf(text, "%s%lu\n", "Virtual Address: ", currentSection.VirtualAddress);
                fprintf(text, "%s%lu\n", "Raw Size: ", currentSection.SizeOfRawData);
                fprintf(text, "%s%lu\n", "Virtual Size: ", currentSection.Misc.VirtualSize);
                fprintf(text, "%s%lu\n", "Physical Address: ", currentSection.Misc.PhysicalAddress);
                fprintf(text, "%s%hu\n", "Number of line numbers: ", currentSection.NumberOfLinenumbers);
                fprintf(text, "%s%hu\n", "Number of relocations: ", currentSection.NumberOfRelocations);
                fprintf(text, "%s%lu\n", "Pointer to line numbers: ", currentSection.PointerToLinenumbers);
                fprintf(text, "%s%lu\n", "Number to relocations: ", currentSection.PointerToRelocations);
                fprintf(text, "%s%lu\n", "Number to raw data: ", currentSection.PointerToRawData);
                fprintf(text, "%s%lX\n\n", "Characteristics: 0x", currentSection.Characteristics);

                if (currentSection.Characteristics & IMAGE_SCN_CNT_CODE) {
                    int seekLast = ftell(fileReader);
                    fseek(fileReader, currentSection.PointerToRawData, SEEK_SET);
                    for (DWORD j = 0; j < currentSection.SizeOfRawData; j++)
                        fprintf(bin, "%X ", fgetc(fileReader));
                    fseek(fileReader, seekLast, SEEK_SET);
                }
            }
            fclose(text);
            fclose(bin);
            fclose(fileReader);
        }
    }
}
