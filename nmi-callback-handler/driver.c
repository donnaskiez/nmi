#include "driver.h"

BOOLEAN ValidateDriverObjectHasBackingModule(
	_In_ PSYSTEM_MODULES ModuleInformation, 
	_In_ PDRIVER_OBJECT DriverObject
)
{
	if (!ModuleInformation || !DriverObject)
		return ERROR;

	for (int i = 0; i < ModuleInformation->module_count; i++)
	{
		RTL_MODULE_EXTENDED_INFO system_module = *(RTL_MODULE_EXTENDED_INFO*)(
			(uintptr_t)ModuleInformation->address + i * sizeof(RTL_MODULE_EXTENDED_INFO));

		if (system_module.ImageBase == DriverObject->DriverStart)
		{
			return TRUE;
		}
	}

	DbgPrint("invalid driver found\n");
	return FALSE;
}

//https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-3-4a0e195d947b
NTSTATUS GetSystemModuleInformation(_Out_ PSYSTEM_MODULES ModuleInformation)
{
	if (!ModuleInformation)
		return STATUS_ABANDONED;

	ULONG size = 0;

	//query system module information without an output buffer to get 
	//number of bytes required to store all module info structures
	if (!NT_SUCCESS(RtlQueryModuleInformation(
		&size,
		sizeof(RTL_MODULE_EXTENDED_INFO),
		NULL
	)))
	{
		DbgPrint("Failed to query module information");
		return STATUS_ABANDONED;
	}

	//allocate pool big enough to store those structures
	PRTL_MODULE_EXTENDED_INFO driver_information = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		size,
		NMI_CB_POOL_TAG
	);

	if (!driver_information)
	{
		DbgPrint("Failed to allocate pool LOL");
		return STATUS_ABANDONED;
	}

	//query the module information again this time passing the output buffer
	//to store module information blocks
	if (!NT_SUCCESS(RtlQueryModuleInformation(
		&size,
		sizeof(RTL_MODULE_EXTENDED_INFO),
		driver_information
	)))
	{
		DbgPrint("Failed lolz");
		return STATUS_ABANDONED;
	}
	
	ModuleInformation->address = driver_information;
	ModuleInformation->module_count = size / sizeof(RTL_MODULE_EXTENDED_INFO);

	return STATUS_SUCCESS;
}

NTSTATUS ValidateDriverObjects(
	_In_ PSYSTEM_MODULES SystemModules, 
	_Out_ PVOID InvalidDriverPool,
	_Out_ int* InvalidDriverCount
)
{
	HANDLE handle;

	OBJECT_ATTRIBUTES attributes = { 0 };
	PVOID directory	= { 0 };

	UNICODE_STRING directory_name;
	RtlInitUnicodeString(&directory_name, L"\\Driver");

	InitializeObjectAttributes(
		&attributes,
		&directory_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(ZwOpenDirectoryObject(
		&handle,
		DIRECTORY_ALL_ACCESS,
		&attributes
	)))
	{
		DbgPrint("Failed to query directory object");
		return STATUS_ABANDONED;
	}

	if (!NT_SUCCESS(ObReferenceObjectByHandle(
		handle,
		DIRECTORY_ALL_ACCESS,
		NULL,
		KernelMode,
		&directory,
		NULL
	)))
	{
		DbgPrint("Failed to reference directory by handle");
		return STATUS_ABANDONED;
	}

	/*
	* Windows organises its drivers in object directories (not the same as 
	* files directories). For the driver directory, there are 37 entries, 
	* each driver is hashed and indexed. If there is a driver with a duplicate
	* index, it is inserted into same index in a linked list using the 
	* _OBJECT_DIRECTORY_ENTRY struct. So to enumerate all drivers we visit
	* each entry in the hashmap, enumerate all objects in the linked list 
	* at entry j then we increment the hashmap index i. The motivation behind
	* this is that when a driver is accessed, it is brought to the first index 
	* in the linked list, so drivers that are accessed the most can be 
	* accessed quickly
	*/

	POBJECT_DIRECTORY directory_object = (POBJECT_DIRECTORY)directory;

	if (!directory_object)
		return STATUS_ABANDONED;

	//Lock directory while we are reading it
	ExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

	for (int i = 0; i < NUMBER_HASH_BUCKETS; i++)
	{
		POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[i];

		if (!entry)
			continue;

		POBJECT_DIRECTORY_ENTRY sub_entry = entry;

		//walk the entries linked list until entry is null
		while (sub_entry)
		{
			PDRIVER_OBJECT current_driver = sub_entry->Object;

			if (!ValidateDriverObjectHasBackingModule(
				SystemModules,
				current_driver
			))
			{
				*InvalidDriverCount += 1;
			}

			sub_entry = sub_entry->ChainLink;
		}
	}

	//Unlock directory + reduce reference counts to object + close handle
	ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
	ObDereferenceObject(directory);
	ZwClose(handle);

	return STATUS_SUCCESS;
}

BOOLEAN IsInstructionPointerInInvalidRegion(
	_In_ UINT64 RIP, 
	_In_ PSYSTEM_MODULES SystemModules
)
{
	if (!RIP || !SystemModules)
		return ERROR;

	for (int i = 0; i < SystemModules->module_count; i++)
	{
		RTL_MODULE_EXTENDED_INFO system_module = *(RTL_MODULE_EXTENDED_INFO*)(
			(uintptr_t)SystemModules->address + i * sizeof(RTL_MODULE_EXTENDED_INFO));

		UINT64 base = system_module.ImageBase;
		UINT64 end = base + system_module.ImageSize;

		if (RIP >= base && RIP <= end)
		{
			DbgPrint("RIP executing within module: %s\n", system_module.FullPathName);
			return TRUE;
		}
	}

	DbgPrint("RIP seems to be executing from within invalid memory\n");
	return FALSE;
}

NTSTATUS AnalyseNmiData(
	_In_ int numCores, 
	_In_ PSYSTEM_MODULES SystemModules
)
{	
	if (!numCores || !SystemModules)
		return STATUS_ABANDONED;

	for (int i = 0; i < numCores; i++)
	{
		NMI_CALLBACK_DATA thread_data = *(NMI_CALLBACK_DATA*)(
			(uintptr_t)thread_data_pool + i * sizeof(NMI_CALLBACK_DATA));

		for (int i = 0; i < thread_data.num_frames_captured; i++)
		{
			DWORD64 stack_frame = *(DWORD64*)(((uintptr_t)thread_data.stack_unwind_pool + i * sizeof(PVOID)));
			BOOLEAN flag = IsInstructionPointerInInvalidRegion(stack_frame, SystemModules);

			if (!flag && flag != ERROR)
			{
				DbgPrint("RIP was executing in invalid region: %llx\n", stack_frame);
			}

		}

		ExFreePoolWithTag(thread_data.stack_unwind_pool, NMI_CB_POOL_TAG);
	}
}

BOOLEAN NmiCallback(_In_ PVOID Context, _In_ BOOLEAN Handled)
{
	//TODO need to implement context so we can check if nmis have been disabled
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Handled);

	DbgPrint("nmi callback called\n");

	//must free each pool after each stack frame has been analysed
	PVOID stack_frames = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x200, NMI_CB_POOL_TAG);

	int num_frames_captured = RtlCaptureStackBackTrace(
		0,
		0x200,
		stack_frames,
		NULL
	);

	//TODO: need to use the context to increment the callback counter to check if nmis
	//have been disabled

	PVOID current_thread = KeGetCurrentThread();

	NMI_CALLBACK_DATA thread_data = { 0 };
	thread_data.kthread_address = (UINT64)current_thread;
	thread_data.kprocess_address = (UINT64)PsGetCurrentProcess();
	thread_data.stack_base = *((UINT64*)((uintptr_t)current_thread + 0x030));
	thread_data.stack_limit = *((UINT64*)((uintptr_t)current_thread + 0x038));
	thread_data.start_address = *((UINT64*)((uintptr_t)current_thread + 0x450));		//can be spoofed but still a decent detection vector
	thread_data.cr3 = __readcr3();
	thread_data.stack_unwind_pool = stack_frames;
	thread_data.num_frames_captured = num_frames_captured;

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
	PKAFFINITY_EX ProcAffinityPool = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAFFINITY_EX), NMI_CB_POOL_TAG);

	if (!ProcAffinityPool)
		return STATUS_FAILED_DRIVER_ENTRY;

	//Register our callback
	PVOID NMICallbackHandle = KeRegisterNmiCallback(NmiCallback, 0);

	if (!NMICallbackHandle)
		return STATUS_FAILED_DRIVER_ENTRY;

	//Count cores (NMI's are sent per core)
	ULONG num_cores = KeQueryActiveProcessorCountEx(0);

	thread_data_pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, num_cores * sizeof(NMI_CALLBACK_DATA), NMI_CB_POOL_TAG);

	if (!thread_data_pool)
		return STATUS_FAILED_DRIVER_ENTRY;

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

	SYSTEM_MODULES modules;

	if (!NT_SUCCESS(GetSystemModuleInformation(&modules)))
	{
		DbgPrint("Failed to enumerate driver objects");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	if (!NT_SUCCESS(AnalyseNmiData(num_cores, &modules)))
	{
		DbgPrint("Failed to analyse the stack walk");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	PVOID drivers = NULL;
	int count = 0;

	if (!NT_SUCCESS(ValidateDriverObjects(&modules, &drivers, &count)))
	{
		DbgPrint("Failed to validate driver objects");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	count > 0
		? DbgPrint("found INVALID drivers with count: %i\n", count)
		: DbgPrint("No INVALID drivers found\n");

	UINT64 test_addr = 18446628139270488814;
	IsInstructionPointerInInvalidRegion(test_addr, &modules);

	//Unregister our callback + free allocated pool
	KeDeregisterNmiCallback(NMICallbackHandle);

	ExFreePoolWithTag(modules.address, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(ProcAffinityPool, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(thread_data_pool, NMI_CB_POOL_TAG);

	return STATUS_SUCCESS;
}
