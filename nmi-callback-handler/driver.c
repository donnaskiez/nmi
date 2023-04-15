#include <ntifs.h>

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

typedef NTSTATUS(NTAPI* ZwGetContextThread_t)(IN HANDLE ThreadHandle, OUT PCONTEXT Context);
ZwGetContextThread_t ZwGetContextThread;

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

BOOLEAN NmiCallback(_In_ PVOID Context, _In_ BOOLEAN Handled)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Handled);

	DbgPrint("nmi callback called");

	/*
	* GS register holds the address of the Thread Information Block
	* We can use the __readgsqword function to read an address by offset
	* from the TIB base
	*/

	PVOID TEB = (PVOID)__readgsqword(0x30);
	DbgPrint("TEB address: %p", TEB);

	PVOID current_thread = PsGetCurrentThread();
	DbgPrint("Current thread: %p", current_thread);

	UINT64 start_address = *((UINT64*)((uintptr_t)current_thread + 0x450));

	//base = lower address, limit = top address as stack grows down on windows
	UINT64 stack_base = *((UINT64*)((uintptr_t)current_thread + 0x030));			
	UINT64 stack_limit = *((UINT64*)((uintptr_t)current_thread + 0x038));

	DbgPrint("start address: %I64u, stack base: %I64u, stack limit: %I64u", start_address, stack_base, stack_limit);

	//RtlCaptureStackBackTrace or StackWalk can be used to do some stackwalking :3

	__debugbreak();

	return TRUE;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);


	UNICODE_STRING usZwGetContextThread;
	RtlInitUnicodeString(&usZwGetContextThread, L"ZwGetContextThread");
	ZwGetContextThread = (ZwGetContextThread_t)MmGetSystemRoutineAddress(&usZwGetContextThread);

	//Allocate a pool for our Processor affinity structures
	PKAFFINITY_EX ProcAffinityPool = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAFFINITY_EX), NMI_CB_POOL_TAG);

	if (!ProcAffinityPool)
		return STATUS_FAILED_DRIVER_ENTRY;

	//Register our callback
	PVOID NMICallbackHandle = KeRegisterNmiCallback(NmiCallback, 0);

	if (!NMICallbackHandle)
		return STATUS_FAILED_DRIVER_ENTRY;

	//Calculate our delay (200ms currently)
	LARGE_INTEGER delay = { 0 };
	delay.QuadPart -= 200 * 10000;

	//Count cores (NMI's are sent per core)
	ULONG num_cores = KeQueryActiveProcessorCountEx(0);

	//Iterate over each logical processor to fire NMI
	for (ULONG core = 0; core < num_cores; core++)
	{
		//Initialize our proc affinity for this core and add it to our structure
		KeInitializeAffinityEx(ProcAffinityPool);
		KeAddProcessorAffinityEx(ProcAffinityPool, core);

		DbgPrint("Sending NMI");

		//Fire our NMI
		HalSendNMI(ProcAffinityPool);

		//Delay sending the NMI to each processor since only 1 NMI can be 
		//active at any one time
		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}

	KeDeregisterNmiCallback(NMICallbackHandle);
	ExFreePoolWithTag(ProcAffinityPool, NMI_CB_POOL_TAG);

	return STATUS_SUCCESS;
}
