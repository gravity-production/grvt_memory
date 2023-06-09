//
// Created by Alexandr on 2/8/2023.
//


#include "process.hpp"

typedef NTSTATUS(NTAPI* NtQueryInformationProcessFunc)(
		HANDLE ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
);

typedef struct _MY_PEB
{
	bool InheritedAddressSpace;
	bool ReadImageFileExecOptions;
	bool BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			bool ImageUsesLargePages : 1;
			bool IsProtectedProcess : 1;
			bool IsImageDynamicallyRelocated : 1;
			bool SkipPatchingUser32Forwarders : 1;
			bool IsPackagedProcess : 1;
			bool IsAppContainer : 1;
			bool IsProtectedProcessLight : 1;
			bool IsLongPathAwareProcess : 1;
		} s1;
	} u1;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
} MY_PEB;

DWORD process::get_pid_by_proc_name(PCSTR name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	memset(&process, 0, sizeof(process));
	process.dwSize = sizeof(process);
	// Walkthrough all processes.
	if (Process32First(snapshot, &process)) {
		do {
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (strcmp(process.szExeFile, name)==0) {
				return process.th32ProcessID;
			}
		}
		while (Process32Next(snapshot, &process));
	}
	return 0;
}
HANDLE process::open_process_by_name(PCSTR process_name)
{
	DWORD pid = get_pid_by_proc_name(process_name);
	if (pid == 0)
		throw std::runtime_error("Process not found");
	HANDLE gma_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!gma_process)
		throw std::runtime_error("Can't open process");
	return gma_process;
}
LPVOID process::get_module_base(HANDLE proc, HMODULE p_module)
{
	MODULEINFO moduleInfo;
	GetModuleInformation(proc, p_module, &moduleInfo, sizeof(moduleInfo));
	return moduleInfo.lpBaseOfDll;
}
DWORD process::get_module_size(HANDLE proc, HMODULE p_module)
{
	MODULEINFO moduleInfo;
	GetModuleInformation(proc, p_module, &moduleInfo, sizeof(moduleInfo));
	return moduleInfo.SizeOfImage;
}

LPVOID process::get_process_base(HANDLE proc)
{
	PROCESS_BASIC_INFORMATION pbi;
	MY_PEB peb = { 0 };
	auto NtQueryInformationProcess =
			reinterpret_cast<NtQueryInformationProcessFunc>(
					GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess")
			);

	NTSTATUS status = NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

	if (NT_SUCCESS(status))
	{
		ReadProcessMemory(proc, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);
	}

	return peb.ImageBaseAddress;
}
