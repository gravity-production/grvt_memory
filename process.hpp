//
// Created by Alexandr on 2/8/2023.
//

#ifndef GMA2PATCH_PROCESS_HPP
#define GMA2PATCH_PROCESS_HPP

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdexcept>

typedef long long int BIN_OFFSET;

class process {
public:
	static DWORD get_pid_by_proc_name(PCSTR process_name);
	static HANDLE open_process_by_name(PCSTR process_name);
	static LPVOID get_module_base(HANDLE proc, HMODULE p_module);
	static DWORD get_module_size(HANDLE proc, HMODULE p_module);
};

#endif //GMA2PATCH_PROCESS_HPP
