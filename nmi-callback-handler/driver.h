#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <intrin.h>

#define NMI_CONTEXT_POOL '7331'
#define STACK_FRAMES_POOL 'loop'
#define INVALID_DRIVER_LIST_HEAD_POOL 'rwar'
#define INVALID_DRIVER_LIST_ENTRY_POOL 'gaah'
#define SYSTEM_MODULES_POOL 'halb'
#define THREAD_DATA_POOL 'doof'
#define PROC_AFFINITY_POOL 'eeee'

#define NUMBER_HASH_BUCKETS 37
#define ERROR -1
#define STACK_FRAME_POOL_SIZE 0x200

#define KTHREAD_STACK_BASE_OFFSET 0x030
#define KTHREAD_STACK_LIMIT_OFFSET 0x038
#define KTHREAD_START_ADDRESS_OFFSET 0x450

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

/* invalid drivers linked list items */

typedef struct _INVALID_DRIVER
{
	struct _INVALID_DRIVER* next;
	PDRIVER_OBJECT driver;

}INVALID_DRIVER, * PINVALID_DRIVER;

typedef struct _INVALID_DRIVERS_HEAD
{
	PINVALID_DRIVER first_entry;
	INT count;		//keeps track of the number of drivers in the list

}INVALID_DRIVERS_HEAD, * PINVALID_DRIVERS_HEAD;

/* system modules information */

typedef struct _SYSTEM_MODULES
{
	PVOID address;
	INT module_count;

}SYSTEM_MODULES, * PSYSTEM_MODULES;

typedef struct _NMI_CONTEXT
{
	INT nmi_callbacks_run;

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
	INT module_count;

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
	INT			num_frames_captured;
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

#endif // !DRIVER_H
