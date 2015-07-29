#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <winnt.h>
#include <winbase.h>
#include <tlhelp32.h>
#include <unistd.h>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <string>

#include "scit.h"


using namespace std;


#define TMP_STR_LEN 32


string dwDebugEventCode2str(DWORD dwDebugEventCode) {
	switch (dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			return "EXCEPTION_DEBUG_EVENT";
		case CREATE_THREAD_DEBUG_EVENT:
			return "CREATE_THREAD_DEBUG_EVENT";
		case CREATE_PROCESS_DEBUG_EVENT:
			return "CREATE_PROCESS_DEBUG_EVENT";
		case EXIT_THREAD_DEBUG_EVENT:
			return "EXIT_THREAD_DEBUG_EVENT";
		case EXIT_PROCESS_DEBUG_EVENT:
			return "EXIT_PROCESS_DEBUG_EVENT";
		case LOAD_DLL_DEBUG_EVENT:
			return "LOAD_DLL_DEBUG_EVENT";
		case UNLOAD_DLL_DEBUG_EVENT:
			return "UNLOAD_DLL_DEBUG_EVENT";
		case OUTPUT_DEBUG_STRING_EVENT:
			return "OUTPUT_DEBUG_STRING_EVENT";
		case RIP_EVENT:
			return "RIP_EVENT";
	}
	
	return "???";
}


string ExceptionCode2string(DWORD ExceptionCode) {
	switch (ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			return "EXCEPTION_ACCESS_VIOLATION";
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
		case EXCEPTION_BREAKPOINT:
			return "EXCEPTION_BREAKPOINT";
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			return "EXCEPTION_DATATYPE_MISALIGNMENT";
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			return "EXCEPTION_FLT_DENORMAL_OPERAND";
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
		case EXCEPTION_FLT_INEXACT_RESULT:
			return "EXCEPTION_FLT_INEXACT_RESULT";
		case EXCEPTION_FLT_INVALID_OPERATION:
			return "EXCEPTION_FLT_INVALID_OPERATION";
		case EXCEPTION_FLT_OVERFLOW:
			return "EXCEPTION_FLT_OVERFLOW";
		case EXCEPTION_FLT_STACK_CHECK:
			return "EXCEPTION_FLT_STACK_CHECK";
		case EXCEPTION_FLT_UNDERFLOW:
			return "EXCEPTION_FLT_UNDERFLOW";
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			return "EXCEPTION_ILLEGAL_INSTRUCTION";
		case EXCEPTION_IN_PAGE_ERROR:
			return "EXCEPTION_IN_PAGE_ERROR";
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			return "EXCEPTION_INT_DIVIDE_BY_ZERO";
		case EXCEPTION_INT_OVERFLOW:
			return "EXCEPTION_INT_OVERFLOW";
		case EXCEPTION_INVALID_DISPOSITION:
			return "EXCEPTION_INVALID_DISPOSITION";
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
		case EXCEPTION_PRIV_INSTRUCTION:
			return "EXCEPTION_PRIV_INSTRUCTION";
		case EXCEPTION_SINGLE_STEP:
			return "EXCEPTION_SINGLE_STEP";
		case EXCEPTION_STACK_OVERFLOW:
			return "EXCEPTION_STACK_OVERFLOW";
	}
	
	return "???";
}


//
//CheckRemoteDebuggerPresent
DWORD WINAPI myIsDebuggerPresent() {
	return FALSE;
}


int main(int argc, char **argv) {
	ScitInjectedProcessDescriptor_t ipd;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DEBUG_EVENT de;
	CONTEXT ctx;
	map<DWORD, HANDLE> mThreadHandles;
	char tmpStr[TMP_STR_LEN];
	EXCEPTION_DEBUG_INFO exception;
	DWORD dwContinueStatus;
	LPCSTR lpDllName;


	if (argc != 2)
		return EXIT_FAILURE;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	if (!CreateProcess((CHAR*) argv[1], 0, 0, 0, 1, DEBUG_ONLY_THIS_PROCESS, 0, 0, &si, &pi)) {
		cout << "Can\'t run: " << argv[1];

		return EXIT_FAILURE;
	}
	if (!scitInjectLocalModule(pi.dwProcessId, pi.dwThreadId, &ipd, TRUE)) {
		cout << "Can\'t inject: " << argv[1];

		return EXIT_FAILURE;
	}

	mThreadHandles[pi.dwThreadId] = pi.hThread;

	if (isWindowsSevenOrLater())
		lpDllName = "api-ms-win-core-processthreads-l1-1-0.dll";
	else
		lpDllName = "kernel32.dll";
		

	if (!scitRemoteHookAPI(ipd, lpDllName, "IsDebuggerPresent", (FARPROC)myIsDebuggerPresent, pi.dwThreadId)) {
		cout << "Can\'t hook: IsDebuggerPresent" << endl;

//		return EXIT_FAILURE;
	}

	memset(&ctx, 0, sizeof(ctx));

	for(;;)
	{
		if (!WaitForDebugEvent(&de, INFINITE))
			break;

		if (mThreadHandles.find(de.dwThreadId) == mThreadHandles.end()) {
			//open thread
			mThreadHandles[de.dwThreadId] = OpenThread(THREAD_ALL_ACCESS, 1, de.dwThreadId);
		}
		
		if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT || de.dwDebugEventCode == RIP_EVENT)
			break;

		memset(&ctx, 0, sizeof(ctx));
		ctx.ContextFlags = CONTEXT_FULL;
		GetThreadContext(mThreadHandles[de.dwThreadId], &ctx);

//if (ctx.EFlags & 0x100)
//	cout << "aaaa" << endl;

		memset(tmpStr, 0, TMP_STR_LEN);
		snprintf(tmpStr, TMP_STR_LEN, "0x%X", (unsigned int)ctx.Eip);

		dwContinueStatus = DBG_CONTINUE;

		if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			exception = de.u.Exception;
			cout << tmpStr << ", " << dwDebugEventCode2str(de.dwDebugEventCode) << " (" << ExceptionCode2string(exception.ExceptionRecord.ExceptionCode) << ")" << endl;
			
			if (
			exception.ExceptionRecord.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION 
//			|| exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
			) {
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			}
		}
		else {
			cout << tmpStr << ", " << dwDebugEventCode2str(de.dwDebugEventCode) << endl;
		}

		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}

system("pause");
	return EXIT_SUCCESS;
}

