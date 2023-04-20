#include <ntifs.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

#define NMI_CB_POOL_TAG 'BCmN'

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
	UINT64	start_address;	
	UINT64	stack_limit;
	UINT64	stack_base;
	PVOID	stack_unwind_pool;
	int		num_frames_captured;
	UINT64	thread_cr3;

}NMI_CALLBACK_DATA, *PNMI_CALLBACK_DATA;

PVOID thread_data_pool;

EXTERN_C VOID KeInitializeAffinityEx(PKAFFINITY_EX affinity);
EXTERN_C VOID KeAddProcessorAffinityEx(PKAFFINITY_EX affinity, INT num);
EXTERN_C VOID HalSendNMI(PKAFFINITY_EX affinity);

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

NTSTATUS AnalyseStackWalk(_In_ int numCores)
{	
	for (int i = 0; i < numCores; i++)
	{
		NMI_CALLBACK_DATA thread_data;

		RtlCopyMemory(
			&thread_data,
			(uintptr_t)thread_data_pool + i * sizeof(NMI_CALLBACK_DATA),
			sizeof(NMI_CALLBACK_DATA)
		);

		DbgPrint("------------------------\n");
		DbgPrint("kthread address: %llx", thread_data.kthread_address);
		DbgPrint("Stack base: %llx\n", thread_data.stack_base);
		DbgPrint("Stack limit: %llx\n", thread_data.stack_limit);
		DbgPrint("start address: %llx\n", thread_data.start_address);
		DbgPrint("cr3: %llx\n", thread_data.thread_cr3);
		DbgPrint("stack frame pointer: %p\n", thread_data.stack_unwind_pool);
		DbgPrint("num frames captured: %i\n", thread_data.num_frames_captured);

		//do stuff

		//free frame pool
		ExFreePoolWithTag(thread_data.stack_unwind_pool, NMI_CB_POOL_TAG);
	}
}

BOOLEAN NmiCallback(_In_ PVOID Context, _In_ BOOLEAN Handled)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Handled);

	DbgPrint("nmi callback called\n");

	//must free each pool after each stack frame has been analysed
	PVOID stack_frames = ExAllocatePoolWithTag(NonPagedPool, 0x200, NMI_CB_POOL_TAG);	

	int num_frames_captured = RtlCaptureStackBackTrace(
		0,
		0x200,
		stack_frames,
		NULL
	);

	PVOID current_thread = KeGetCurrentThread();
	DbgPrint("Current thread: %p\n", current_thread);

	NMI_CALLBACK_DATA thread_data = { 0 };
	thread_data.kthread_address = (UINT64)current_thread;
	thread_data.stack_base = *((UINT64*)((uintptr_t)current_thread + 0x030));
	thread_data.stack_limit = *((UINT64*)((uintptr_t)current_thread + 0x038));
	thread_data.start_address = *((UINT64*)((uintptr_t)current_thread + 0x450));		//can be spoofed but still a decent detection vector
	thread_data.thread_cr3 = __readcr3();
	thread_data.stack_unwind_pool = stack_frames;
	thread_data.num_frames_captured = num_frames_captured;

	DbgPrint("Current stack frame address: %p\n", stack_frames);

	ULONG proc_num = KeGetCurrentProcessorNumber();

	RtlCopyMemory(
		((uintptr_t)thread_data_pool) + proc_num * sizeof(thread_data),
		&thread_data,
		sizeof(thread_data)
	);

	return TRUE;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	//Allocate a pool for our Processor affinity structures
	PKAFFINITY_EX ProcAffinityPool = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAFFINITY_EX), NMI_CB_POOL_TAG);

	if (!ProcAffinityPool)
		return STATUS_FAILED_DRIVER_ENTRY;

	//Register our callback
	PVOID NMICallbackHandle = KeRegisterNmiCallback(NmiCallback, 0);

	if (!NMICallbackHandle)
		return STATUS_FAILED_DRIVER_ENTRY;

	//Count cores (NMI's are sent per core)
	ULONG num_cores = KeQueryActiveProcessorCountEx(0);

	thread_data_pool = ExAllocatePoolWithTag(NonPagedPool, num_cores * sizeof(NMI_CALLBACK_DATA), NMI_CB_POOL_TAG);

	//Calculate our delay (200ms currently)
	LARGE_INTEGER delay = { 0 };
	delay.QuadPart -= 200 * 10000;

	//Iterate over each logical processor to fire NMI
	for (ULONG core = 0; core < num_cores; core++)
	{
		//Bind the interrupted thread to the logical processor its running on
		KeInitializeAffinityEx(ProcAffinityPool);
		KeAddProcessorAffinityEx(ProcAffinityPool, core);

		DbgPrint("Sending NMI\n");

		//Fire our NMI
		HalSendNMI(ProcAffinityPool);

		//Delay sending the NMI to each processor since only 1 NMI can be 
		//active at any one time
		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}

	AnalyseStackWalk(num_cores);

	//Unregister our callback + free allocated pool
	KeDeregisterNmiCallback(NMICallbackHandle);
	ExFreePoolWithTag(ProcAffinityPool, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(thread_data_pool, NMI_CB_POOL_TAG);

	return STATUS_SUCCESS;
}
