/*
This file is part of DosBox Injector.

DosBox Injector is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DosBox Injector is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DosBox Injector.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "scit.h"

void _scitReleaseAndUnloadModule(HANDLE hProcess, DWORD dwProcessId, LPCSTR lpLibPath, PVOID lpRemoteAddress, DWORD dwFreeMode, void *buffer2free, void *lpDwSectionsProtect, ScitInjectedProcessDescriptor_t *ipd) {
	DWORD dwLastError = GetLastError();

	if (lpRemoteAddress)
		VirtualFreeEx(hProcess, lpRemoteAddress, 0, MEM_RELEASE);

	if (lpDwSectionsProtect)
	{
		free(lpDwSectionsProtect);
		lpDwSectionsProtect = 0;
	}

	if (hProcess)
		CloseHandle(hProcess);

	if (buffer2free) {
		free(buffer2free);
		buffer2free = 0;
	}

	scitUninjectLocalModule(ipd);
	scitFreeDescriptor(ipd);

	SetLastError(dwLastError);
}

DWORD scitCallInjectedModuleMethod(ScitInjectedProcessDescriptor_t ipd, LPTHREAD_START_ROUTINE lpRemoteFunc, LPVOID lpParameter, DWORD dwParameterLength, DWORD dwThreadId) {
	HANDLE hRemoteThread;
	DWORD dwThreadExitCode;
	DWORD dwRemoteFunction = (DWORD) lpRemoteFunc;
	DWORD dwDelta;
	ScitFunctionArguments_t arg;
	LPVOID lpArgRemoteAddress = 0;
	BOOL bInjected;
	DWORD dwSizeWritten;
	DEBUG_EVENT de;

	if (!ipd.hInjectedModule || !ipd.hProcess || !lpRemoteFunc)
		return 0;

	/* use address of currently loaded executable will be the same in remote loaded */
	dwDelta = (DWORD) ipd.hInjectedModule - (DWORD) GetModuleHandle(0);
	dwRemoteFunction += dwDelta;
	lpRemoteFunc = (LPTHREAD_START_ROUTINE) dwRemoteFunction;

	if (lpParameter && dwParameterLength)
	{
		/* inject parameter within ScitFunctionArguments_t */
		arg.lpArg = VirtualAllocEx(ipd.hProcess, NULL, dwParameterLength, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
		arg.dwArgLength = dwParameterLength;
		arg.dwType = 0;

		if (!arg.lpArg)
			return 0;

		lpArgRemoteAddress = VirtualAllocEx(ipd.hProcess, NULL, sizeof(arg), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
		if (!lpArgRemoteAddress)
		{
			VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);

			return 0;
		}

		/* write param */
		bInjected = WriteProcessMemory(ipd.hProcess, arg.lpArg, lpParameter, dwParameterLength, &dwSizeWritten);
		if (!bInjected)
		{
			VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);
			VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);

			return 0;
		}

		bInjected = WriteProcessMemory(ipd.hProcess, lpArgRemoteAddress, &arg, sizeof(arg), &dwSizeWritten);
		if (!bInjected)
		{
			VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);

			return 0;
		}
	}

	hRemoteThread = CreateRemoteThread(ipd.hProcess, NULL, 0, lpRemoteFunc, lpArgRemoteAddress, 0, NULL);
	if (!hRemoteThread)
	{
		if (lpArgRemoteAddress)
			VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);
		if (arg.lpArg)
			VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);

		return FALSE;
	}

	do {
		if (dwThreadId) {
			/*
			 * hack: process and its main thrad was started with flags DEBUG_ONLY_THIS_PROCESS and/or CREATE_SUSPENDED
			 * so we must "run" it manually to get dwThreadExitCode
			 */
			 WaitForDebugEvent(&de, INFINITE);
		}
		
		GetExitCodeThread(hRemoteThread, (LPDWORD)&dwThreadExitCode);
		
		if (dwThreadId) {
			/*
			 * hack for DEBUG_ONLY_THIS_PROCESS and/or CREATE_SUSPENDED flags
			 */ 
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		}
	} while (dwThreadExitCode == STILL_ACTIVE);

	/* free args */
	if (lpArgRemoteAddress)
		VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);
	if (arg.lpArg)
		VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);

	/*printf("%x\n", dwThreadExitCode);*/

	return dwThreadExitCode;
}

void _scitFixImports(HMODULE hInjectedModule, unsigned char *imageBuffer, DWORD dwImageBufferLen) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) imageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((DWORD) imageBuffer + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	PIMAGE_THUNK_DATA pImageThunkData;
	PIMAGE_IMPORT_BY_NAME pImageImportByName;
	DWORD lpInjectedModuleImportOffset;
	DWORD lpInjectedModuleImportThunkOffset;
	char dllName[512], funcName[512];
	HINSTANCE hModule;
	DWORD dwJmpAddr;
	DWORD dwDelta;
	DWORD i;

	if ((DWORD) hInjectedModule == pNtHeader->OptionalHeader.ImageBase)
		return;

	dwDelta = (DWORD) hInjectedModule - pNtHeader->OptionalHeader.ImageBase;

	for (i = 0; i < pNtHeader->OptionalHeader.SizeOfImage; i++) {
		/*
		 * following two instructions (FF,25) depends on CPU family
		 * FF, 25 means FAR JMP used in win32
		 */
		if (imageBuffer[i] == 0xFF && imageBuffer[i + 1] == 0x25) {
			memcpy(&dwJmpAddr, &imageBuffer[i + 2], sizeof(DWORD));

			if (dwJmpAddr >= pNtHeader->OptionalHeader.ImageBase && dwJmpAddr <= pNtHeader->OptionalHeader.ImageBase + pNtHeader->OptionalHeader.SizeOfImage) {
				/*printf("%x -> %x\n", dwJmpAddr, dwJmpAddr + dwDelta);*/

				dwJmpAddr += dwDelta;
				memcpy(&imageBuffer[i + 2], &dwJmpAddr, sizeof(DWORD));
			}
		}
	}

	lpInjectedModuleImportOffset = (DWORD) imageBuffer + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	do {
		pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) lpInjectedModuleImportOffset;
		if (!pImageImportDescriptor->FirstThunk)
			break;

		/* read imported DLL name */
		memset(dllName, 0, sizeof(dllName));
		memcpy(dllName, imageBuffer + pImageImportDescriptor->Name, sizeof(dllName));

		/* now me must load a DLL itself to get remote function address */
		hModule = LoadLibrary(dllName);
		/* hModule holds now a image base, we can use it to get RVA of remote function*/

		lpInjectedModuleImportThunkOffset = (DWORD) imageBuffer + pImageImportDescriptor->FirstThunk;
		do {
			pImageThunkData = (PIMAGE_THUNK_DATA) lpInjectedModuleImportThunkOffset;
			if (!pImageThunkData->u1.Function)
				break;

			/* read imported function name */
			memset(funcName, 0, sizeof(funcName));
			memcpy(funcName, imageBuffer + pImageThunkData->u1.Function + sizeof(pImageImportByName->Hint), sizeof(funcName));

			/*
			 * get address of remote function - experimental - we should get function addreess
			 * direct from loaded module, not our module - TODO
			 */
			dwJmpAddr = (DWORD) GetProcAddress(hModule, funcName);

			/* printf("%x -> %x\n", pImageThunkData->u1.Function, dwJmpAddr); */
			/* change function address */
			pImageThunkData->u1.Function = dwJmpAddr;

			lpInjectedModuleImportThunkOffset += sizeof(IMAGE_THUNK_DATA);
		} while (pImageThunkData->u1.Function);

		lpInjectedModuleImportOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	} while (pImageImportDescriptor->FirstThunk);
}

void _scitFixRelocations(HMODULE hInjectedModule, char *imageBuffer, DWORD dwImageBufferLen) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) imageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((DWORD) imageBuffer + pDosHeader->e_lfanew);
	DWORD lpBaseRelocOffset, dwNextReloc;
	PIMAGE_BASE_RELOCATION imageRelocation;
	unsigned char *lpByteArray;
	DWORD dwValue;
	DWORD dwDelta;
	WORD wEntry;
	WORD wAddr;
	WORD wType;
	WORD wRva;
	DWORD i;

	if ((DWORD) hInjectedModule == pNtHeader->OptionalHeader.ImageBase)
		return;

	dwDelta = (DWORD) hInjectedModule - pNtHeader->OptionalHeader.ImageBase;

	lpBaseRelocOffset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	dwNextReloc = (DWORD) imageBuffer + lpBaseRelocOffset;

	do {
		imageRelocation = (PIMAGE_BASE_RELOCATION) dwNextReloc;
		if (!imageRelocation->VirtualAddress)
			break;

		lpByteArray = (unsigned char*) imageRelocation;
		for (i = sizeof(IMAGE_BASE_RELOCATION); i < imageRelocation->SizeOfBlock; i += sizeof(WORD)) {
			memcpy(&wEntry, (const void*) ((DWORD) lpByteArray + i), sizeof(WORD));

			wType = (wEntry & 0xF000) >> 12;
			wAddr = wEntry & 0x0FFF;
			wRva = imageRelocation->VirtualAddress + wAddr;

			if (wType == IMAGE_REL_BASED_HIGHLOW) {
				memcpy(&dwValue, (const void*) ((DWORD) imageBuffer + wRva), sizeof(DWORD));

				if (dwValue - pNtHeader->OptionalHeader.ImageBase <= 0 || dwValue - pNtHeader->OptionalHeader.ImageBase > pNtHeader->OptionalHeader.SizeOfImage)
					continue;

				/* printf("[%x]: %x -> %x\n", (DWORD) hInjectedModule + wRva, dwValue, dwValue + dwDelta); */

				dwValue += dwDelta;

				memcpy((void*) ((DWORD) imageBuffer + wRva), &dwValue, sizeof(DWORD));
			}
		}

		dwNextReloc += imageRelocation->SizeOfBlock;
	} while (imageRelocation->VirtualAddress);
}


BOOL isWindowsLowerXP() {
	OSVERSIONINFOEX osInfo;

	memset(&osInfo, 0, sizeof(osInfo));
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	GetVersionEx((LPOSVERSIONINFO) &osInfo);

	return osInfo.dwMajorVersion < 5 && osInfo.dwMinorVersion < 1;
}


BOOL isWindowsSevenOrLater() {
	OSVERSIONINFOEX osInfo;

	memset(&osInfo, 0, sizeof(osInfo));
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	GetVersionEx((LPOSVERSIONINFO) &osInfo);

	return osInfo.dwMajorVersion >= 6 && osInfo.dwMinorVersion && osInfo.wProductType == VER_NT_WORKSTATION;
}


BOOL scitInjectLocalModuleByExeName(LPCSTR lpExeName, LPCSTR lpLibPath, ScitInjectedProcessDescriptor_t *ipd, BOOL force) {
	DWORD aProcesses[4096], cbNeeded, cProcesses;
	TCHAR szProcessName[MAX_PATH];
	TCHAR szDupLibPath[MAX_PATH];
	DWORD dwProcessId;
	HANDLE hProcess;
	DWORD i;

	if (!lpLibPath)
		GetModuleFileName(0, szDupLibPath, MAX_PATH);
	else
		strncpy(szDupLibPath, lpLibPath, MAX_PATH);

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return FALSE;

	cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < (int) cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            dwProcessId = aProcesses[i];

            hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
            if (hProcess)
            {
                GetModuleBaseName(hProcess, 0, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
                CloseHandle(hProcess);

                if (!strcasecmp(szProcessName, lpExeName))
                {
                    return scitInjectModule(dwProcessId, 0, szDupLibPath, ipd, force);
                }
            }
        }
    }

	return FALSE;
}


BOOL scitInjectLocalModule(DWORD dwProcessId, DWORD dwThreadId, ScitInjectedProcessDescriptor_t *ipd, BOOL force) {
	TCHAR szCurrentModulePath[MAX_PATH];
	
	GetModuleFileName(0, szCurrentModulePath, MAX_PATH);
	return scitInjectModule(dwProcessId, dwThreadId, szCurrentModulePath, ipd, force);
}


BOOL scitInjectModule(DWORD dwProcessId, DWORD dwThreadId, LPCSTR lpLibPath, ScitInjectedProcessDescriptor_t *ipd, BOOL force) {
	DWORD dwLibPathSize;
	HMODULE hKernel32;
	HANDLE hProcess = 0;
	LPVOID lpRemoteAddress = 0;
	BOOL bInjected;
	DWORD dwSizeWritten;
	unsigned char *imageBuffer = 0;
	HANDLE hRemoteThread;
	DWORD dwThreadExitCode;
	HMODULE hInjectedModule;
	HMODULE hModule;
	BOOL bReaded;
	DWORD dwSizeReaded;
	LPVOID lpHeaderOffset;
	LPVOID lpSectionOffset;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	IMAGE_DOS_HEADER dosCurrentHeader;
	IMAGE_NT_HEADERS ntCurrentHeader;
	IMAGE_SECTION_HEADER section;
	MEMORY_BASIC_INFORMATION memoryBasicInformation;
	DWORD dwOldProtect, dwOldProtect_;
	DWORD *lpDwSectionsProtect = 0;
	DEBUG_EVENT de;
	DWORD i;

	if (!lpLibPath || !ipd)
		return FALSE;

	if (dwProcessId == SCIT_CURRENT_PROCESS)
		dwProcessId = GetCurrentProcessId();

	ipd->hProcess = 0;
	ipd->dwProcessId = dwProcessId;
	ipd->lpLibPath = strdup(lpLibPath);
	ipd->hInjectedModule = 0;

	if (!ipd->lpLibPath)
	{
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	dwLibPathSize = strlen(lpLibPath);

	hKernel32 = GetModuleHandle("KERNEL32.DLL");
	if(!hKernel32) {
		hKernel32 = GetModuleHandle("kernel32.dll");
		if (!hKernel32)
		{
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION, FALSE, dwProcessId);
	if (!hProcess)
	{
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	/* get image base of current module */
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), 0, 0, NULL);
	if (!hRemoteThread) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	do {
		if (dwThreadId) {
			/*
			 * hack: process and its main thrad was started with flags DEBUG_ONLY_THIS_PROCESS and/or CREATE_SUSPENDED
			 * so we must "run" it manually to get dwThreadExitCode
			 */
			 WaitForDebugEvent(&de, INFINITE);
		}
		
		GetExitCodeThread(hRemoteThread, (LPDWORD)&dwThreadExitCode);
		
		if (dwThreadId) {
			/*
			 * hack for DEBUG_ONLY_THIS_PROCESS and/or CREATE_SUSPENDED flags
			 */ 
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		}
	} while (dwThreadExitCode == STILL_ACTIVE);
	hModule = (HMODULE) dwThreadExitCode;

	CloseHandle(hRemoteThread);

	/* read DOS and PE headers of current module */
	bReaded = ReadProcessMemory(hProcess, (LPVOID) ((DWORD) hModule), &dosCurrentHeader, sizeof(dosCurrentHeader), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	if (dosCurrentHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	/* read PE header */
	lpHeaderOffset = (LPVOID) ((DWORD) hModule + (DWORD) dosCurrentHeader.e_lfanew);
	bReaded = ReadProcessMemory(hProcess, lpHeaderOffset, &ntCurrentHeader, sizeof(ntCurrentHeader), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	if (ntCurrentHeader.FileHeader.NumberOfSections <= 0)
	{
		/* wrong file? */
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	lpSectionOffset = (LPVOID) ((DWORD) hModule + (DWORD) dosCurrentHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for (i = 0; i < ntCurrentHeader.FileHeader.NumberOfSections; i++)
	{
		bReaded = ReadProcessMemory(hProcess, (LPVOID) ((DWORD) lpSectionOffset + (i * sizeof(section))), &section, sizeof(section), &dwSizeReaded);
		if (!bReaded) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		if ((section.Characteristics & IMAGE_SCN_CNT_CODE) && (section.Characteristics & IMAGE_SCN_MEM_WRITE))
		{
			/* strange - code section have write flag, maybe it's packed/compressed
			 * so we can wait until it will be ready for infection
			 */
			
			if (!force) {
				_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

				return FALSE;
			}
		}
	}

	/* alloc remote memory */
	lpRemoteAddress = VirtualAllocEx(hProcess, NULL, dwLibPathSize + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (!lpRemoteAddress) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	bInjected = WriteProcessMemory(hProcess, lpRemoteAddress, (LPVOID)lpLibPath, dwLibPathSize, &dwSizeWritten);
	if (!bInjected) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	/* check if DLL is already injected... */
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	do {
		if (dwThreadId) {
			/* same hack as above */
			WaitForDebugEvent(&de, INFINITE);
		}
		
		GetExitCodeThread(hRemoteThread, &dwThreadExitCode);
		
		if (dwThreadId)
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
	} while (dwThreadExitCode == STILL_ACTIVE);
	hInjectedModule = (HMODULE) dwThreadExitCode;

	CloseHandle(hRemoteThread);

	/* DLL already injected? */
	if (hInjectedModule) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	do {
		if (dwThreadId) {
			/* same hack as above */
			WaitForDebugEvent(&de, INFINITE);
		}

		GetExitCodeThread(hRemoteThread, (LPDWORD)&dwThreadExitCode);
		
		if (dwThreadId)
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
	} while (dwThreadExitCode == STILL_ACTIVE);
	hInjectedModule = (HMODULE) dwThreadExitCode;

	CloseHandle(hRemoteThread);

	/* free module name buffer */
	VirtualFreeEx(hProcess, lpRemoteAddress, 0, MEM_RELEASE);
	lpRemoteAddress = 0;

	/* read DOS header */
	bReaded = ReadProcessMemory(hProcess, (LPVOID) hInjectedModule, &dosHeader, sizeof(dosHeader), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	/* read PE header */
	lpHeaderOffset = (LPVOID) ((DWORD) hInjectedModule + (DWORD) dosHeader.e_lfanew);
	bReaded = ReadProcessMemory(hProcess, lpHeaderOffset, &ntHeader, sizeof(ntHeader), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return FALSE;
	}

	if (ntHeader.OptionalHeader.ImageBase != (DWORD) hInjectedModule) {
		lpDwSectionsProtect = (LPDWORD) malloc(IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(DWORD));
		if (!lpDwSectionsProtect)
		{
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		/* get memory regions protect information */
		for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			lpDwSectionsProtect[i] = 0;

			if (ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress && ntHeader.OptionalHeader.DataDirectory[i].Size)
			{
				if (VirtualQueryEx(hProcess, (LPVOID) ((DWORD) hInjectedModule + ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress), &memoryBasicInformation, ntHeader.OptionalHeader.DataDirectory[i].Size))
				{
					if (memoryBasicInformation.AllocationProtect)
						lpDwSectionsProtect[i] = memoryBasicInformation.AllocationProtect;

					/* printf("%x, %d, %x\n", ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress, ntHeader.OptionalHeader.DataDirectory[i].Size, lpDwSectionsProtect[i]); */
				}

			}

			/* printf("%x\n", lpDwSectionsProtect[i]); */
		}

		if (!(imageBuffer = (unsigned char*) malloc(ntHeader.OptionalHeader.SizeOfImage + 1))) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		/* unlock memory before read/write */
		if (!VirtualProtectEx(hProcess, (LPVOID) hInjectedModule, ntHeader.OptionalHeader.SizeOfImage, PAGE_READWRITE, &dwOldProtect)) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		bReaded = ReadProcessMemory(hProcess, (LPVOID) hInjectedModule, imageBuffer, ntHeader.OptionalHeader.SizeOfImage, &dwSizeReaded);
		if (!bReaded) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		_scitFixRelocations(hInjectedModule, (char*)imageBuffer, ntHeader.OptionalHeader.SizeOfImage);
		_scitFixImports(hInjectedModule, imageBuffer, ntHeader.OptionalHeader.SizeOfImage);

		/* write module image back to process */
		bInjected = WriteProcessMemory(hProcess, (LPVOID) hInjectedModule, imageBuffer, ntHeader.OptionalHeader.SizeOfImage, &dwSizeWritten);
		if (!bInjected) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		/* restore old lock */
		if (!VirtualProtectEx(hProcess, (LPVOID) hInjectedModule, ntHeader.OptionalHeader.SizeOfImage, dwOldProtect, &dwOldProtect_)) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return FALSE;
		}

		/* restore protect for each section */
 		for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			if (ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress && ntHeader.OptionalHeader.DataDirectory[i].Size && lpDwSectionsProtect[i])
			{
				if (!VirtualProtectEx(hProcess, (LPVOID) hInjectedModule, ntHeader.OptionalHeader.SizeOfImage, lpDwSectionsProtect[i], &dwOldProtect)) {
					_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

					return FALSE;
				}
			}

			/* printf("%x\n", lpDwSectionsProtect[i]); */
		}

		free(imageBuffer);
		imageBuffer = 0;
	}

	ipd->hProcess = hProcess;
	ipd->hInjectedModule = hInjectedModule;

	return TRUE;
}

void scitFreeDescriptor(ScitInjectedProcessDescriptor_t *ipd)
{
	if (ipd->lpLibPath)
		free(ipd->lpLibPath);

	ipd->hProcess = 0;
	ipd->dwProcessId = 0;
	ipd->lpLibPath = 0;
	ipd->hInjectedModule = 0;
}

BOOL scitUninjectLocalModule(ScitInjectedProcessDescriptor_t *ipd) {
	HANDLE hRemoteThread;
	LPVOID lpRemoteAddress;
	BOOL bUninjected;
	DWORD dwThreadExitCode;
	DWORD dwSizeWritten;
	DWORD dwSize;
	HMODULE hKernel32;
	HMODULE hModule;

	if (!ipd->lpLibPath || !ipd->hProcess)
		return FALSE;

	if (ipd->dwProcessId == SCIT_CURRENT_PROCESS)
		ipd->dwProcessId = GetCurrentProcessId();

	dwSize = strlen(ipd->lpLibPath);

	hKernel32 = GetModuleHandle("KERNEL32.DLL");
	if(!hKernel32) {
		hKernel32 = GetModuleHandle("kernel32.dll");
		if (!hKernel32)
			return FALSE;
	}

	lpRemoteAddress = VirtualAllocEx(ipd->hProcess, NULL, dwSize + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (!lpRemoteAddress)
		return FALSE;

	bUninjected = WriteProcessMemory(ipd->hProcess, lpRemoteAddress, (LPVOID) ipd->lpLibPath, dwSize, &dwSizeWritten);
	if (!bUninjected)
		return FALSE;

	/* check if DLL is already injected... */
	hRemoteThread = CreateRemoteThread(ipd->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread)
		return FALSE;

	do {
		GetExitCodeThread(hRemoteThread, &dwThreadExitCode);
	} while (dwThreadExitCode == STILL_ACTIVE);

	CloseHandle(hRemoteThread);

	hModule = (HMODULE) dwThreadExitCode;

	/* DLL already injected? */
	if (!hModule)
		return FALSE;

	hRemoteThread = CreateRemoteThread(ipd->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread)
		return FALSE;

	do {
		GetExitCodeThread(hRemoteThread, &dwThreadExitCode);
	} while (dwThreadExitCode == STILL_ACTIVE);

	hModule = (HMODULE) dwThreadExitCode;

	if (!hModule)
		return FALSE;

	CloseHandle(hRemoteThread);

	hRemoteThread = CreateRemoteThread(ipd->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "FreeLibrary"), hModule, 0, NULL);
	if (!hRemoteThread)
		return FALSE;

	do {
		GetExitCodeThread(hRemoteThread, (LPDWORD)&dwThreadExitCode);
	} while (dwThreadExitCode == STILL_ACTIVE);

	CloseHandle(hRemoteThread);

	if (ipd->hProcess)
	{
		VirtualFreeEx(ipd->hProcess, lpRemoteAddress, 0, MEM_RELEASE);
		CloseHandle(ipd->hProcess);
	}

	scitFreeDescriptor(ipd);

	return dwThreadExitCode > 0;
}


PIMAGE_THUNK_DATA _scitGetLoadedExeAPIFunctionThunkData(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpOldHandler) {
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	PIMAGE_THUNK_DATA pImageThunkData;
	DWORD lpInjectedModuleImportOffset;
	DWORD lpInjectedModuleImportThunkOffset;
	char dllName[512];
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	HMODULE hDll;
	HMODULE hMainModule;
	BOOL bLoadedEarlier = TRUE;

	if (!lpDllName || !lpApiName)
		return FALSE;

	hMainModule = GetModuleHandle(lpMainModuleName);
	if (!hMainModule)
		return FALSE;

	if ((hDll = GetModuleHandle(lpDllName)) != NULL)
	{
		bLoadedEarlier = TRUE;
	}
	else
	{
		hDll = LoadLibrary(lpDllName);
		if (!hDll)
			return 0;
	}

	if (!fpOldHandler)
	{
		fpOldHandler = (FARPROC) GetProcAddress(hDll, lpApiName);
		if (!fpOldHandler)
			return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER) hMainModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	pNtHeader = (PIMAGE_NT_HEADERS) ((int) hMainModule + (int) pDosHeader->e_lfanew);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		if (!bLoadedEarlier)
			FreeLibrary(hDll);

		return 0;
	}

	if (!pNtHeader->FileHeader.NumberOfSections) {
		if (!bLoadedEarlier)
			FreeLibrary(hDll);

		return 0;
	}

	if (!pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		if (!bLoadedEarlier)
			FreeLibrary(hDll);

		return 0;
	}

	lpInjectedModuleImportOffset = (DWORD) hMainModule + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	do {
		pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) lpInjectedModuleImportOffset;
		if (!pImageImportDescriptor->FirstThunk)
			break;

		/* read imported DLL name */
		memset(dllName, 0, sizeof(dllName));
		memcpy(dllName, (void*) ((DWORD) hMainModule + pImageImportDescriptor->Name), sizeof(dllName));

		if (!strcasecmp(dllName, lpDllName)) {
			lpInjectedModuleImportThunkOffset = (DWORD) hMainModule + pImageImportDescriptor->FirstThunk;
			do {
				pImageThunkData = (PIMAGE_THUNK_DATA) lpInjectedModuleImportThunkOffset;
				if (!pImageThunkData->u1.Function)
					break;

				if ((DWORD) fpOldHandler == (DWORD) pImageThunkData->u1.Function)
					return pImageThunkData;

				lpInjectedModuleImportThunkOffset += sizeof(IMAGE_THUNK_DATA);
			} while (pImageThunkData->u1.Function);

			break;
		}

		lpInjectedModuleImportOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	} while (pImageImportDescriptor->FirstThunk);

	return 0;
}


DWORD WINAPI _scitRemoteHookAPI(ScitFunction_t *function) {
	MessageBox(0, "", "_scitRemoteHookAPI", 0);
	return 0;
}


FARPROC scitRemoteHookAPI(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, DWORD dwThreadId) {
	ScitFunction_t function;
	
	memset(&function, 0, sizeof(function));
	
	function.fpHandler = fpHandler;
	strncpy(function.lpDllName, lpDllName, SCIT_DLL_NAME_LEN);
	strncpy(function.lpApiName, lpApiName, SCIT_API_NAME_LEN);
	
	return (FARPROC)scitCallInjectedModuleMethod(ipd, (LPTHREAD_START_ROUTINE)_scitRemoteHookAPI, &function, sizeof(function), dwThreadId);
}


FARPROC _scitHookAPI(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, FARPROC fpOldHandler, DWORD dwHookType, BOOL bHook) {
	PIMAGE_THUNK_DATA pImageThunkData;
	FARPROC _fpOldHandler = 0;
	HANDLE hProcess;
	DWORD dwOldProtect, dwOldProtect_;

	if (bHook)
		pImageThunkData = _scitGetLoadedExeAPIFunctionThunkData(lpMainModuleName, lpDllName, lpApiName, 0);
	else
		pImageThunkData = _scitGetLoadedExeAPIFunctionThunkData(lpMainModuleName, lpDllName, lpApiName, fpHandler);

	if (pImageThunkData && pImageThunkData->u1.Function)
	{
		_fpOldHandler = (FARPROC) pImageThunkData->u1.Function;

		hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
		if (!hProcess)
			return 0;

		/* unlock memory before read/write */
		if (!VirtualProtectEx(hProcess, (LPVOID) pImageThunkData, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &dwOldProtect))
			return 0;

		/* replace address */
		if (bHook)
			pImageThunkData->u1.Function = (DWORD) fpHandler;
		else
			pImageThunkData->u1.Function = (DWORD) fpOldHandler;

		/* restore old lock */
		if (!VirtualProtectEx(hProcess, (LPVOID) pImageThunkData, sizeof(IMAGE_THUNK_DATA), dwOldProtect, &dwOldProtect_))
			return 0;

		CloseHandle(hProcess);
	}

	return _fpOldHandler;
}

FARPROC scitHookAPI(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, DWORD dwHookType) {
	return _scitHookAPI(lpMainModuleName, lpDllName, lpApiName, fpHandler, 0, dwHookType, TRUE);
}

FARPROC scitUnhookAPI(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, FARPROC fpOldHandler, DWORD dwHookType) {
	return _scitHookAPI(lpMainModuleName, lpDllName, lpApiName, fpHandler, fpOldHandler, dwHookType, FALSE);
}
