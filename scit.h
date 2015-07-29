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

#ifndef _SCIT_H_
#define _SCIT_H_

#include <windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <psapi.h>

#define SCIT_CURRENT_PROCESS  0
#define SCIT_ALL_PROCESSES   -1

/* hook types for scitHookAPI & scitUnhookAPI */
#define SCIT_HOOK_HOST_IAT 1

#define SCIT_DLL_NAME_LEN 256
#define SCIT_API_NAME_LEN 256


typedef struct ScitInjectedProcessDescriptor_s {
	HANDLE hProcess;
	DWORD dwProcessId;
	LPSTR lpLibPath;
	HMODULE hInjectedModule;
} ScitInjectedProcessDescriptor_t;

typedef struct ScitFunctionArgument_s {
	LPVOID lpArg;
	DWORD dwArgLength;
	DWORD dwType;  /* not used */
} ScitFunctionArguments_t;

typedef struct ScitFunction_s {
	CHAR lpDllName[256];
	CHAR lpApiName[256];
	FARPROC fpHandler;
} ScitFunction_t;

#ifdef __cplusplus 
extern "C" {
#endif

/* public */
BOOL isWindowsSevenOrLater();
BOOL isWindowsLowerXP();
BOOL scitInjectLocalModule(DWORD dwProcessId, DWORD dwThreadId, ScitInjectedProcessDescriptor_t *ipd, BOOL force);
BOOL scitInjectModule(DWORD dwProcessId, DWORD dwThreadId, LPCSTR lpLibPath, ScitInjectedProcessDescriptor_t *ipd, BOOL force);
FARPROC scitHookAPI(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, DWORD dwHookType);
FARPROC scitUnhookAPI(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, FARPROC fpOldHandler, DWORD dwHookType);
DWORD scitCallInjectedModuleMethod(ScitInjectedProcessDescriptor_t ipd, LPTHREAD_START_ROUTINE lpRemoteFunc, LPVOID lpParameter, DWORD dwParameterLength, DWORD dwThreadId);
BOOL scitUninjectLocalModule(ScitInjectedProcessDescriptor_t *ipd);
void scitFreeDescriptor(ScitInjectedProcessDescriptor_t *ipd);
BOOL scitInjectLocalModuleByExeName(LPCSTR lpExeName, LPCSTR lpLibPath, ScitInjectedProcessDescriptor_t *ipd, BOOL force);
FARPROC scitRemoteHookAPI(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, DWORD dwThreadId);

/* protected */
void _scitReleaseAndUnloadModule(HANDLE hProcess, DWORD dwProcessId, LPCSTR lpLibPath, PVOID lpRemoteAddress, DWORD dwFreeMode, void *buffer2free, void *lpDwSectionsProtect, ScitInjectedProcessDescriptor_t *ipd);
void _scitFixImports(HMODULE hInjectedModule, unsigned char *imageBuffer, DWORD dwImageBufferLen);
void _scitFixRelocations(HMODULE hInjectedModule, char *imageBuffer, DWORD dwImageBufferLen);
PIMAGE_THUNK_DATA _scitGetLoadedExeAPIFunctionThunkData(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpOldHandler);
FARPROC _scitHookAPI(LPCSTR lpMainModuleName, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, FARPROC fpOldHandler, DWORD dwHookType, BOOL bHook);
DWORD WINAPI _scitRemoteHookAPI(ScitFunction_t *function);

#ifdef __cplusplus 
}
#endif

#endif  /* _SCIT_H_ */
