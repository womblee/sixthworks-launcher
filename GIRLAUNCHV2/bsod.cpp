#include "bsod.hpp"
#include <Windows.h>
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

void blue_screen()
{
	BOOLEAN Boolean;
	ULONG Response;

	RtlAdjustPrivilege(19, TRUE, FALSE, &Boolean); // Enable SeShutdownPrivilege
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
}