#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <winnt.h>
#include <winbase.h>
#include <tlhelp32.h>
#include <unistd.h>
#include <stdio.h>

#include "libdasm-beta/libdasm.h"

#define TMP_STR_LEN 32
#define MAX_HANDLES 1024


typedef struct Breakpoint {
	DWORD   dwAddress;
	BYTE	baOriginalCode[10];
	DWORD 	dwOriginalCodeLength;
	BOOL	bPlaced;
} Breakpoint_t;


BOOL _WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
	DWORD dwOriginalProtect = 0;
	DWORD dwTmpProtect = 0;


	if (!VirtualProtectEx(hProcess, (LPVOID) lpBaseAddress, nSize, PAGE_EXECUTE_READWRITE, &dwOriginalProtect)) {
		return 0;
	}

	if (!WriteProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)) {
		return 0;
	}

	//restore old protect
	if (!VirtualProtectEx(hProcess, (LPVOID) lpBaseAddress, nSize, dwOriginalProtect, &dwTmpProtect)) {
		return 0;
	}

    if (!FlushInstructionCache(hProcess, 0, 0)) {
        return 0;
    }

	return 1;
}


Breakpoint_t removeBreakpoint(HANDLE hProcess, Breakpoint_t bpx) {
	unsigned char bData[2];
	SIZE_T sNumberOfBytesRead;
	SIZE_T sNumberOfBytesWritten;
	unsigned char bBpData[] = { 0xEB, 0xFE };


	if (!bpx.bPlaced) {
		return bpx;
	}

	//check if breakpoint still exists in code - if not - code can be changed by other application thread - exit
	if (!ReadProcessMemory(hProcess, (LPVOID)bpx.dwAddress, bData, sizeof(bData), &sNumberOfBytesRead)) {
		return bpx;
	}

	//compare breakpoint data with code at specified address
	if (bData[0] != bBpData[0] || bData[1] != bBpData[1]) {
		//breakpoint does not exists - can be removed by app thread
		bpx.bPlaced = 0;
		return bpx;
	}

	//ok breakpoint exists - restore original code
	sNumberOfBytesWritten = 0;
	if (!_WriteProcessMemory(hProcess, (LPVOID)bpx.dwAddress, bpx.baOriginalCode, sizeof(bData), &sNumberOfBytesWritten)) {
		return bpx;
	}

	bpx.bPlaced = 0;
	return bpx;
}


Breakpoint_t putBreakpoint(HANDLE hProcess, DWORD dwAddress, BOOL bForce) {
	Breakpoint_t bpx;
	SIZE_T sNumberOfBytesRead;
	SIZE_T sNumberOfBytesWritten;
	MEMORY_BASIC_INFORMATION memoryBasicInfo;
	DWORD dwOriginalProtect = 0;
	DWORD dwTmpProtect = 0;
	unsigned char bBpData[] = { 0xEB, 0xFE };
    INSTRUCTION inst;
    int insLen;


	memset(&bpx, 0, sizeof(bpx));

	bpx.dwOriginalCodeLength = sizeof(bpx.baOriginalCode);
    bpx.dwAddress = dwAddress;

    do {
        sNumberOfBytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPVOID)bpx.dwAddress, bpx.baOriginalCode, bpx.dwOriginalCodeLength, &sNumberOfBytesRead)) {
            int ddd = GetLastError();
            return bpx;
        }

        insLen = get_instruction(&inst, bpx.baOriginalCode, MODE_32);
        if (insLen <= 0) {
            //unsupported instruction
            return bpx;
        }
        if (insLen < sizeof(bBpData)) {
            if (!bForce) {
                //no space for bp
                return bpx;
            }
        }
        else {
            break;
        }

        bpx.dwAddress += insLen;
    } while (1);

    sNumberOfBytesWritten = 0;
    if (!_WriteProcessMemory(hProcess, (LPVOID)bpx.dwAddress, bBpData, sizeof(bBpData), &sNumberOfBytesWritten)) {
        return bpx;
    }

	bpx.bPlaced = 1;

	return bpx;
}


int getProcessEntryPoint(const char *cszFilename) {
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	FILE *f;


	if (!cszFilename)
		return 0;

	f = fopen(cszFilename, "rb");
	if (f) {
		if (fread(&dosHeader, 1, sizeof(dosHeader), f) != sizeof(dosHeader)) {
			fclose(f);
			return 0;
		}

		if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
			fclose(f);
			return 0;
		}

		if (fseek(f, dosHeader.e_lfanew, SEEK_SET) != 0) {
			fclose(f);
			return 0;
		}

		if (fread(&ntHeader, 1, sizeof(ntHeader), f) != sizeof(ntHeader)) {
			fclose(f);
			return 0;
		}

		if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
			fclose(f);
			return 0;
		}

		fclose(f);

		return ntHeader.OptionalHeader.ImageBase + ntHeader.OptionalHeader.AddressOfEntryPoint;
	}

	return 0;
}


BOOL runnded = FALSE;

BOOL singleStepThread(HANDLE hThread, HANDLE hZombieThread) {
	if (hZombieThread) {
		SuspendThread(hZombieThread);
	}

    if (ResumeThread(hThread) == -1 || SuspendThread(hThread) == -1) {
        return 0;
    }

	if (hZombieThread) {
		ResumeThread(hZombieThread);
	}

    return 1;
}


int main(int argc, char **argv) {
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	CONTEXT context;
	DWORD dwLastEip = 0;
	Breakpoint_t bpx;
	DWORD dwEP;
	INSTRUCTION inst;
	int insLen;
	unsigned char bData[10];
	SIZE_T sNumberOfBytesRead;
	BOOL bAttached;
	BOOL bResumed;
	DWORD dwInstructionDisplacement;
	long dwNextInstructionAddress;
    HANDLE hProcess;
    char instructionStr[512];
    FARPROC fpExitProcess;
    FARPROC fpSwitchToThread;
    PVOID pZombieThreadCode;
    PVOID pZombieControl;
    DWORD dwSizeWritten;
    HANDLE hZombieThread;
    HANDLE hZombieThread2;
    FARPROC fpSleep;
    unsigned char bZombieCode[] = {
        0x90,
        0x8B, 0x6C, 0x24, 0x04,
        0x83, 0x7D, 0x00, 0x01,
        0x75, 0xFA,
        0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x8B, 0x45, 0x04,
        0x6A, 0x00,
        0xFF, 0xD0,
        0x90,
        0xEB, 0xE9
    };

    unsigned char bZombieControl[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

/*
002F0000   CC               INT3
002F0001   8B6C24 04        MOV EBP,DWORD PTR SS:[ESP+4]
002F0005   837D 00 01       CMP DWORD PTR SS:[EBP],1
002F0009   90               NOP
002F000A   90               NOP
002F000B   C745 00 00000000 MOV DWORD PTR SS:[EBP],0
002F0012   8B45 04          MOV EAX,DWORD PTR SS:[EBP+4]
002F0015   6A 00            PUSH 0
002F0017   FFD0             CALL EAX
002F0019   90               NOP
002F001A  ^EB E9            JMP SHORT 002F0005
*/

	if (argc != 2) {
		return EXIT_FAILURE;
    }

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

    if (!CreateProcess(
		(CHAR*) argv[1],
		0,
		0,
		0,
		0,

		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,

		0, 0, &si, &pi
	)) {
		return EXIT_FAILURE;
	}

    fpSleep = GetProcAddress(GetModuleHandle("kernel32.dll"), "Sleep");
    fpSwitchToThread = GetProcAddress(GetModuleHandle("kernel32.dll"), "SwitchToThread");

	dwEP = getProcessEntryPoint((CHAR*) argv[1]);
	if (!dwEP) {
		TerminateProcess(pi.hProcess, -1);
		return EXIT_FAILURE;
	}

    printf("Entry point: %.8X\n", dwEP);

	//put breakpoint on an entry point
	bpx = putBreakpoint(pi.hProcess, dwEP, TRUE);
	if (!bpx.bPlaced) {
		TerminateProcess(pi.hProcess, -1);
		return EXIT_FAILURE;
	}

    printf("Main breakpoint set at: %.8X\n", bpx.dwAddress);

    ResumeThread(pi.hThread);

	//wait until app reach its entry point
	do {
        memset(&context, 0, sizeof(context));
		context.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(pi.hThread, &context) && context.Eip != dwLastEip) {
			dwLastEip = context.Eip;

			if (context.Eip == bpx.dwAddress) {
				//breakpoint reached at entry point
				printf("Main breakpoint reached at: 0x%.8X\n", context.Eip);

				break;
			}
		}
	} while (WaitForSingleObject(pi.hThread, 1));

    SuspendThread(pi.hThread);

    if (bpx.bPlaced) {
        //remove breakpoint
        bpx = removeBreakpoint(pi.hProcess, bpx);
        if (bpx.bPlaced) {
            TerminateProcess(pi.hProcess, -1);
            return EXIT_FAILURE;
        }
    }

	//entry point reached, now we can continue execution of main thread step by step
//    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetPriorityClass(pi.hProcess, BELOW_NORMAL_PRIORITY_CLASS);

    //create zombie thread
    pZombieThreadCode = VirtualAllocEx(pi.hProcess, NULL, sizeof(bZombieCode), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pZombieThreadCode) {
        TerminateProcess(pi.hProcess, -1);
        return EXIT_FAILURE;
    }

    pZombieControl = VirtualAllocEx(pi.hProcess, NULL, sizeof(bZombieControl), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pZombieControl) {
        TerminateProcess(pi.hProcess, -1);
        return EXIT_FAILURE;
    }

    memcpy(&bZombieControl[4], &fpSleep, 4);
    if (!_WriteProcessMemory(pi.hProcess, pZombieControl, bZombieControl, sizeof(bZombieControl), &dwSizeWritten)) {
        TerminateProcess(pi.hProcess, -1);
        return EXIT_FAILURE;
    }

    if (!_WriteProcessMemory(pi.hProcess, pZombieThreadCode, bZombieCode, sizeof(bZombieCode), &dwSizeWritten)) {
        TerminateProcess(pi.hProcess, -1);
        return EXIT_FAILURE;
    }

    hZombieThread = CreateRemoteThread(pi.hProcess, NULL, 0, pZombieThreadCode, pZombieControl, 0, NULL);
    if (!hZombieThread) {
        TerminateProcess(pi.hProcess, -1);
        return EXIT_FAILURE;
    }

    Sleep(3000);

//    hZombieThread2 = CreateRemoteThread(pi.hProcess, NULL, 0, pZombieThreadCode, pZombieControl, 0, NULL);
//    if (!hZombieThread2) {
//        TerminateProcess(pi.hProcess, -1);
//        return EXIT_FAILURE;
//    }

//    SetThreadPriority(hZombieThread, THREAD_PRIORITY_HIGHEST);
//    SetThreadPriority(pi.hThread, THREAD_PRIORITY_BELOW_NORMAL);
    SetThreadPriority(hZombieThread, THREAD_PRIORITY_LOWEST);
//    SetThreadPriority(hZombieThread2, THREAD_PRIORITY_LOWEST);
    SetThreadPriority(pi.hThread, THREAD_PRIORITY_LOWEST);
//SetThreadPriority(pi.hThread, THREAD_PRIORITY_HIGHEST);

	dwLastEip = 0;


    do {
//        Sleep(1000);

		//at this point thread should be still suspended
//        memset(&context, 0, sizeof(context));
		context.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(pi.hThread, &context) && context.Eip != dwLastEip) {
			dwLastEip = context.Eip;

            printf("0x%.8X\n", dwLastEip);

//            printf("0x%.8X\n", context.Eip);
//            printf("0x%.8X\r", context.Eip);
		}

        if (!singleStepThread(pi.hThread, hZombieThread)) {
            break;
        }
    } while (WaitForSingleObject(pi.hThread, 1));

//    ResumeThread(pi.hThread);
system("pause");
return 1;

	do {
        Sleep(0);

        //"single step" thread (restored instruction)
        if (!singleStepThread(pi.hThread, hZombieThread)) {
            break;
        }

		//at this point thread should be still suspended
        memset(&context, 0, sizeof(context));
		context.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(pi.hThread, &context) && context.Eip != dwLastEip) {
			dwLastEip = context.Eip;

//            printf("0x%.8X\r", context.Eip);
            printf("0x%.8X\n", context.Eip);
		}
    } while (WaitForSingleObject(pi.hThread, 0));

	TerminateProcess(pi.hProcess, -1);

	printf("\n");
	system("pause");
	return EXIT_SUCCESS;
}
