#include "anti_bad.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "xorstr.h"
#include <vector>

std::vector<std::string> BadWindowClassList
{
	xorstr_("OLLYDBG"),
	xorstr_("Zeta Debugger"),
	xorstr_("Rock Debugger"),
	xorstr_("ObsidianGUI"),
	xorstr_("ID"),
	xorstr_("WinDbgFrameClass"),
	xorstr_("idawindow"),
	xorstr_("tnavbox"),
	xorstr_("idaview"),
	xorstr_("tgrzoom")
};

std::vector<wchar_t*> BadProcessnameList
{
	xorstr_(L"ollydbg.exe"),
	xorstr_(L"ida.exe"),
	xorstr_(L"ida64.exe"),
	xorstr_(L"idag.exe"),
	xorstr_(L"idag64.exe"),
	xorstr_(L"idaw.exe"),
	xorstr_(L"idaw64.exe"),
	xorstr_(L"idaq.exe"),
	xorstr_(L"idaq64.exe"),
	xorstr_(L"idau.exe"),
	xorstr_(L"idau64.exe"),
	xorstr_(L"scylla.exe"),
	xorstr_(L"scylla_x64.exe"),
	xorstr_(L"scylla_x86.exe"),
	xorstr_(L"protection_id.exe"),
	xorstr_(L"x64dbg.exe"),
	xorstr_(L"x32dbg.exe"),
	xorstr_(L"windbg.exe"),
	xorstr_(L"reshacker.exe"),
	xorstr_(L"ImportREC.exe"),
	xorstr_(L"IMMUNITYDEBUGGER.EXE")
};

std::vector<std::string> BadWindowTextList
{
	xorstr_("OLLYDBG"),
	xorstr_("ida"),
	xorstr_("disassembly"),
	xorstr_("scylla"),
	xorstr_("Debug"),
	xorstr_("[CPU"),
	xorstr_("Immunity"),
	xorstr_("WinDbg"),
	xorstr_("x32dbg"),
	xorstr_("x64dbg"),
	xorstr_("Import reconstructor")
};

bool is_sniffing()
{
	for (const auto& rc : BadWindowTextList)
	{
		if (FindWindowA(NULL, rc.c_str()))
			return true;
	}

	for (const auto& rc : BadWindowClassList)
	{
		if (FindWindowA(rc.c_str(), NULL))
			return true;
	}

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			if (entry.th32ProcessID != GetCurrentProcessId())
			{
				for (const auto& rc : BadProcessnameList)
				{
					if (!_wcsicmp(entry.szExeFile, rc))
						return true;
				}
			}
		}
	}
	CloseHandle(snapshot);

	return false;
}

void to_lower(unsigned char* input)
{
	char* p = (char*)input;
	unsigned long length = strlen(p);
	for (unsigned long i = 0; i < length; i++) p[i] = tolower(p[i]);
}

int check_virtual()
{
	HKEY h_key = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, xorstr_(L"HARDWARE\\ACPI\\DSDT\\VBOX__"), 0, KEY_READ, &h_key) == ERROR_SUCCESS)
		return 1;

	if (CreateFile(xorstr_(L"\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE)
		return 1;

	if (LoadLibrary(xorstr_(L"VBoxHook.dll")))
		return 1;

	h_key = 0;
	if ((ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"), 0, KEY_READ, &h_key)) && h_key)
	{
		RegCloseKey(h_key);
		return 1;
	}

	h_key = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, xorstr_(L"HARDWARE\\DESCRIPTION\\System"), 0, KEY_READ, &h_key) == ERROR_SUCCESS)
	{
		unsigned long type = 0;
		unsigned long size = 0x100;
		char* systembiosversion = (char*)LocalAlloc(LMEM_ZEROINIT, size + 10);
		if (ERROR_SUCCESS == RegQueryValueEx(h_key, xorstr_(L"SystemBiosVersion"), 0, &type, (unsigned char*)systembiosversion, &size))
		{
			to_lower((unsigned char*)systembiosversion);
			if (type == REG_SZ || type == REG_MULTI_SZ)
			{
				if (strstr(systembiosversion, xorstr_("vbox")))
					return 1;
			}
		}
		LocalFree(systembiosversion);

		type = 0;
		size = 0x200;
		char* videobiosversion = (char*)LocalAlloc(LMEM_ZEROINIT, size + 10);
		if (ERROR_SUCCESS == RegQueryValueEx(h_key, xorstr_(L"VideoBiosVersion"), 0, &type, (unsigned char*)videobiosversion, &size))
		{
			if (type == REG_MULTI_SZ)
			{
				char* video = videobiosversion;
				while (*(unsigned char*)video)
				{
					to_lower((unsigned char*)video);
					if (strstr(video, xorstr_("oracle")) || strstr(video, xorstr_("virtualbox")))
						return 1;

					video = &video[strlen(video) + 1];
				}
			}
		}
		LocalFree(videobiosversion);
		RegCloseKey(h_key);
	}

	HANDLE h = CreateFile(xorstr_(L"\\\\.\\pipe\\VBoxTrayIPC"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h);
		return 1;
	}

	unsigned long pnsize = 0x1000;
	char* s_provider = (char*)LocalAlloc(LMEM_ZEROINIT, pnsize);
	wchar_t w_provider[0x1000];
	mbstowcs(w_provider, s_provider, strlen(s_provider) + 1);

	h_key = 0;
	const char* s_subkey = xorstr_("SYSTEM\\CurrentControlSet\\Enum\\IDE");
	wchar_t w_subkey[22];
	mbstowcs(w_subkey, s_subkey, strlen(s_subkey) + 1);
	if ((ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, w_subkey, 0, KEY_READ, &h_key)) && h_key)
	{
		unsigned long n_subkeys = 0;
		unsigned long max_subkey_length = 0;
		if (ERROR_SUCCESS == RegQueryInfoKey(h_key, 0, 0, 0, &n_subkeys, &max_subkey_length, 0, 0, 0, 0, 0, 0))
		{
			//n_subkeys is usually 2
			if (n_subkeys)
			{
				char* s_new_key = (char*)LocalAlloc(LMEM_ZEROINIT, max_subkey_length + 1);
				for (unsigned long i = 0; i < n_subkeys; i++)
				{
					memset(s_new_key, 0, max_subkey_length + 1);
					HKEY h_new_key = 0;

					wchar_t w_key_new[2048];
					mbstowcs(w_key_new, s_new_key, strlen(s_new_key) + 1);

					if (ERROR_SUCCESS == RegEnumKey(h_key, i, w_key_new, max_subkey_length + 1))
					{
						if ((RegOpenKeyEx(h_key, w_key_new, 0, KEY_READ, &h_new_key) == ERROR_SUCCESS) && h_new_key)
						{
							unsigned long nn = 0;
							unsigned long maxlen = 0;
							RegQueryInfoKey(h_new_key, 0, 0, 0, &nn, &maxlen, 0, 0, 0, 0, 0, 0);
							char* s_newer_key = (char*)LocalAlloc(LMEM_ZEROINIT, maxlen + 1);
							wchar_t w_key_newer[2048];
							mbstowcs(w_key_newer, s_newer_key, strlen(s_newer_key) + 1);
							if (RegEnumKey(h_new_key, 0, w_key_newer, maxlen + 1) == ERROR_SUCCESS)
							{
								HKEY HKKK = 0;
								if (RegOpenKeyEx(h_new_key, w_key_newer, 0, KEY_READ, &HKKK) == ERROR_SUCCESS)
								{
									unsigned long size = 0xFFF;
									unsigned char value_name[0x1000] = { 0 };
									if (RegQueryValueEx(h_new_key, xorstr_(L"FriendlyName"), 0, 0, value_name, &size) == ERROR_SUCCESS)
									{ 
										to_lower(value_name); 

										if (strstr((char*)value_name, xorstr_("vbox")))
										    return 1; 
									}
									RegCloseKey(HKKK);
								}
							}
							LocalFree(w_key_newer);
							LocalFree(s_newer_key);
							RegCloseKey(h_new_key);
						}
					}
				}
				LocalFree(s_new_key);
			}
		}
		RegCloseKey(h_key);
	}
	
	return 0;
}

int cpu_debug_registers()
{
	CONTEXT ctx = { 0 };
	HANDLE h_thread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(h_thread, &ctx))
	{
		return ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00)) ? 1 : 0;
	}

	return 0;
}

int debug_string()
{
	SetLastError(0);
	OutputDebugStringA(xorstr_("anti-debugging test."));

	return (GetLastError() != 0) ? 1 : 0;
}

int close_handle_exception() {
	// invalid handle
	HANDLE h_invalid = (HANDLE)0xDEADBEEF;

	__try
	{
		CloseHandle(h_invalid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// if we get the exception, we return the right code.
		return 1;
	}

	return 0;
}

const wchar_t* get_string(std::string value) {

	return std::wstring(value.begin(), value.end()).c_str();
}

int write_buffer() {
	// vars to store the amount of accesses to the buffer and the granularity for GetWriteWatch()
	ULONG_PTR hits;
	DWORD granularity;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		return 1;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return 1;
	}

	// read the buffer once
	buffer[0] = 1234;

	hits = 4096;
	if (GetWriteWatch(0, buffer, 4096, addresses, &hits, &granularity) != 0)
		return 1;

	else
	{
		// free the memory again
		VirtualFree(addresses, 0, MEM_RELEASE);
		VirtualFree(buffer, 0, MEM_RELEASE);

		// we should have 1 hit if everything is fine
		return (hits == 1) ? 0 : 1;
	}

	// second option

	BOOL result = FALSE, error = FALSE;

	addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL)
		return 1;

	buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return 1;
	}

	// make some calls where a buffer *can* be written to, but isn't actually edited because we pass invalid parameters	
	if (GlobalGetAtomName(INVALID_ATOM, (LPTSTR)buffer, 1) != FALSE || GetEnvironmentVariable(get_string(xorstr_("antidbg")), (LPWSTR)buffer, 4096 * 4096) != FALSE || GetBinaryType(get_string(xorstr_("%random_environment_var_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%")), (LPDWORD)buffer) != FALSE
		|| HeapQueryInformation(0, (HEAP_INFORMATION_CLASS)69, buffer, 4096, NULL) != FALSE || ReadProcessMemory(INVALID_HANDLE_VALUE, (LPCVOID)0x69696969, buffer, 4096, NULL) != FALSE
		|| GetThreadContext(INVALID_HANDLE_VALUE, (LPCONTEXT)buffer) != FALSE || GetWriteWatch(0, &write_buffer, 0, NULL, NULL, (PULONG)buffer) == 0) {
		result = false;
		error = true;
	}

	if (error == FALSE)
	{
		// all calls failed as they're supposed to
		hits = 4096;
		if (GetWriteWatch(0, buffer, 4096, addresses, &hits, &granularity) != 0)
		{
			result = FALSE;
		}
		else
		{
			// should have zero reads here because GlobalGetAtomName doesn't probe the buffer until other checks have succeeded
			// if there's an API hook or debugger in here it'll probably try to probe the buffer, which will be caught here
			result = hits != 0;
		}
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}