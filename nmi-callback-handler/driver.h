#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <intrin.h>

#define NMI_CB_POOL_TAG 'BCmN'

typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[20];

} KAFFINITY_EX, * PKAFFINITY_EX;

EXTERN_C VOID KeInitializeAffinityEx(PKAFFINITY_EX affinity);
EXTERN_C VOID KeAddProcessorAffinityEx(PKAFFINITY_EX affinity, INT num);
EXTERN_C VOID HalSendNMI(PKAFFINITY_EX affinity);

typedef struct _NMI_CALLBACK_DATA
{
	UINT64	kthread_address;
	UINT64	kprocess_address;
	UINT64	start_address;
	UINT64	stack_limit;
	UINT64	stack_base;
	PVOID	stack_unwind_pool;
	int		num_frames_captured;
	UINT64	cr3;

}NMI_CALLBACK_DATA, * PNMI_CALLBACK_DATA;

PVOID thread_data_pool;

/*
Thread Information Block: (GS register)

	SEH frame:						0x00
	Stack Base:						0x08
	Stack Limit:					0x10
	SubSystemTib:					0x18
	Fiber Data:						0x20
	Arbitrary Data:					0x28
	TEB:							0x30
	Environment Pointer:			0x38
	Process ID:						0x40
	Current Thread ID:				0x48
	Active RPC Handle:				0x50
	Thread Local Storage Array:		0x58
	PEB:							0x60
	Last error number:				0x68
	Count Owned Critical Sections:  0x6C
	CSR Client Thread:				0x70
	Win32 Thread Information:		0x78
	...
*/

#endif // !DRIVER_H
