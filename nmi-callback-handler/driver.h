#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <intrin.h>

#define NMI_CB_POOL_TAG 'BCmN'
#define NUMBER_HASH_BUCKETS 37
#define ERROR -1

PVOID thread_data_pool;
PVOID stack_frames;
PVOID nmi_context;

/* invalid drivers linked list items */

typedef struct _INVALID_DRIVER
{
	struct _INVALID_DRIVER* next;
	PDRIVER_OBJECT driver;

}INVALID_DRIVER, * PINVALID_DRIVER;

typedef struct _INVALID_DRIVERS_HEAD
{
	PINVALID_DRIVER first_entry;
	int count;		//keeps track of the number of drivers in the list

}INVALID_DRIVERS_HEAD, * PINVALID_DRIVERS_HEAD;

/* system modules information */

typedef struct _SYSTEM_MODULES
{
	PVOID address;
	int module_count;

}SYSTEM_MODULES, * PSYSTEM_MODULES;

typedef struct _NMI_CONTEXT
{
	int nmi_callbacks_run;

}NMI_CONTEXT, *PNMI_CONTEXT;

/* driver objects information */

/*
*  Driver objects are different from system modules.
*  A manually mapped driver will call IoCreateDevice, 
*  passing in a PDEVICE_OBJECT allocated on the stack
*  and thus will appear in the device objects directory
*  however these objects will not be in the
*  PsLoadedModuleList as they are invalid drivers
*/


typedef struct _DRIVER_OBJECTS
{
	PVOID address;
	int module_count;

}DRIVER_OBJECTS, *PDRIVER_OBJECTS;

/* data gathered during nmi callback */

typedef struct _NMI_CALLBACK_DATA
{
	UINT64		kthread_address;
	UINT64		kprocess_address;
	UINT64		start_address;
	UINT64		stack_limit;
	UINT64		stack_base;
	uintptr_t	stack_frames_offset;
	int			num_frames_captured;
	UINT64		cr3;

}NMI_CALLBACK_DATA, * PNMI_CALLBACK_DATA;

/* windows types */

typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[20];

} KAFFINITY_EX, * PKAFFINITY_EX;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	struct _OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;

} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[NUMBER_HASH_BUCKETS];
	EX_PUSH_LOCK Lock;
	struct _DEVICE_MAP* DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;

} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP
{
	struct _OBJECT_DIRECTORY* DosDevicesDirectory;
	struct _OBJECT_DIRECTORY* GlobalDosDevicesDirectory;
	ULONG ReferenceCount;
	ULONG DriveMap;
	UCHAR DriveType[32];

} DEVICE_MAP, * PDEVICE_MAP;

typedef struct _RTL_MODULE_EXTENDED_INFO
{
	PVOID ImageBase;
	ULONG ImageSize;
	USHORT FileNameOffset;
	CHAR FullPathName[0x100];

} RTL_MODULE_EXTENDED_INFO, * PRTL_MODULE_EXTENDED_INFO;

/* undocumented functions */

EXTERN_C VOID KeInitializeAffinityEx(
	PKAFFINITY_EX affinity
);

EXTERN_C VOID KeAddProcessorAffinityEx(
	PKAFFINITY_EX affinity,
	INT num
);

EXTERN_C VOID HalSendNMI(
	PKAFFINITY_EX affinity
);

NTSTATUS
RtlQueryModuleInformation(
	ULONG* InformationLength,
	ULONG SizePerModule,
	PVOID InformationBuffer);

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

/*
	
   _KTRAP_FRAME (amd64)

   +0x000 P1Home           : Uint8B
   +0x008 P2Home           : Uint8B
   +0x010 P3Home           : Uint8B
   +0x018 P4Home           : Uint8B
   +0x020 P5               : Uint8B
   +0x028 PreviousMode     : Char
   +0x028 InterruptRetpolineState : UChar
   +0x029 PreviousIrql     : UChar
   +0x02a FaultIndicator   : UChar
   +0x02a NmiMsrIbrs       : UChar
   +0x02b ExceptionActive  : UChar
   +0x02c MxCsr            : Uint4B
   +0x030 Rax              : Uint8B
   +0x038 Rcx              : Uint8B
   +0x040 Rdx              : Uint8B
   +0x048 R8               : Uint8B
   +0x050 R9               : Uint8B
   +0x058 R10              : Uint8B
   +0x060 R11              : Uint8B
   +0x068 GsBase           : Uint8B
   +0x068 GsSwap           : Uint8B
   +0x070 Xmm0             : _M128A
   +0x080 Xmm1             : _M128A
   +0x090 Xmm2             : _M128A
   +0x0a0 Xmm3             : _M128A
   +0x0b0 Xmm4             : _M128A
   +0x0c0 Xmm5             : _M128A
   +0x0d0 FaultAddress     : Uint8B
   +0x0d0 ContextRecord    : Uint8B
   +0x0d8 Dr0              : Uint8B
   +0x0e0 Dr1              : Uint8B
   +0x0e8 Dr2              : Uint8B
   +0x0f0 Dr3              : Uint8B
   +0x0f8 Dr6              : Uint8B
   +0x100 Dr7              : Uint8B
   +0x108 DebugControl     : Uint8B
   +0x110 LastBranchToRip  : Uint8B
   +0x118 LastBranchFromRip : Uint8B
   +0x120 LastExceptionToRip : Uint8B
   +0x128 LastExceptionFromRip : Uint8B
   +0x130 SegDs            : Uint2B
   +0x132 SegEs            : Uint2B
   +0x134 SegFs            : Uint2B
   +0x136 SegGs            : Uint2B
   +0x138 TrapFrame        : Uint8B
   +0x140 Rbx              : Uint8B
   +0x148 Rdi              : Uint8B
   +0x150 Rsi              : Uint8B
   +0x158 Rbp              : Uint8B
   +0x160 ErrorCode        : Uint8B
   +0x160 ExceptionFrame   : Uint8B
   +0x168 Rip              : Uint8B
   +0x170 SegCs            : Uint2B
   +0x172 Fill0            : UChar
   +0x173 Logging          : UChar
   +0x174 Fill1            : [2] Uint2B
   +0x178 EFlags           : Uint4B
   +0x17c Fill2            : Uint4B
   +0x180 Rsp              : Uint8B
   +0x188 SegSs            : Uint2B
   +0x18a Fill3            : Uint2B
   +0x18c Fill4            : Uint4B
*/

#endif // !DRIVER_H
