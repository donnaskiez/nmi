#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <intrin.h>

#define NMI_CB_POOL_TAG 'BCmN'
#define NUMBER_HASH_BUCKETS 37

PVOID thread_data_pool;

typedef struct _INVALID_DRIVERS
{
	LIST_ENTRY list_entry;
	PDRIVER_OBJECT driver;

}INVALID_DRIVERS, * PINVALID_DRIVERS;

typedef struct _SYSTEM_MODULES
{
	PVOID address;
	int module_count;

}SYSTEM_MODULES, * PSYSTEM_MODULES;

typedef struct _INVALID_DRIVERS_HEAD
{
	PINVALID_DRIVERS first_entry;
	int count;

}INVALID_DRIVERS_HEAD, *PINVALID_DRIVERS_HEAD;

typedef struct _DRIVER_OBJECTS
{
	PVOID address;
	int module_count;

}DRIVER_OBJECTS, *PDRIVER_OBJECTS;

/* windows types */

typedef struct _KAFFINITY_EX
{
	USHORT Count;
	USHORT Size;
	ULONG Reserved;
	ULONGLONG Bitmap[20];

} KAFFINITY_EX, * PKAFFINITY_EX;

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
