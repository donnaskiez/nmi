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

VOID InitDriverList(_In_ PINVALID_DRIVERS_HEAD ListHead)
{
	ListHead->count = 0;
	ListHead->first_entry = NULL;
}

VOID AddDriverToList(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead, 
	_In_ PDRIVER_OBJECT Driver
)
{
	PINVALID_DRIVER new_entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVER), NMI_CB_POOL_TAG);

	if (!new_entry)
		return;

	new_entry->driver = Driver;
	new_entry->next = InvalidDriversHead->first_entry;
	InvalidDriversHead->first_entry = new_entry;
}

VOID RemoveInvalidDriverFromList(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead)
{
	if (InvalidDriversHead->first_entry)
	{
		PINVALID_DRIVER entry = InvalidDriversHead->first_entry;
		InvalidDriversHead->first_entry = InvalidDriversHead->first_entry->next;
		ExFreePoolWithTag(entry, NMI_CB_POOL_TAG);
	}
}

VOID EnumerateInvalidDrivers(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead)
{
	PINVALID_DRIVER entry = InvalidDriversHead->first_entry;

	while (entry != NULL)
	{
		DbgPrint("Invalid Driver: %wZ\n", entry->driver->DriverName);
		entry = entry->next;
	}
}

NTSTATUS ValidateDriverObjects(
	_In_ PSYSTEM_MODULES SystemModules, 
	_In_ PINVALID_DRIVERS_HEAD InvalidDriverListHead
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
				InvalidDriverListHead->count += 1;
				AddDriverToList(InvalidDriverListHead, current_driver);
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

		UINT64 base = (UINT64)system_module.ImageBase;
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

	//should check start addresses here for invalid system threads

	for (int i = 0; i < numCores; i++)
	{
		NMI_CALLBACK_DATA thread_data = *(NMI_CALLBACK_DATA*)(
			(uintptr_t)thread_data_pool + i * sizeof(NMI_CALLBACK_DATA));

		PNMI_CONTEXT context = (PNMI_CONTEXT)((uintptr_t)nmi_context + i * sizeof(NMI_CONTEXT));

		context->nmi_callbacks_run == 0
			? DbgPrint("no callbacks were run, nmis could have been disabled")
			: DbgPrint("callback count: %i", context->nmi_callbacks_run);

		for (int i = 0; i < thread_data.num_frames_captured; i++)
		{
			DWORD64 stack_frame = *(DWORD64*)(((uintptr_t)stack_frames + thread_data.stack_frames_offset + i * sizeof(PVOID)));
			BOOLEAN flag = IsInstructionPointerInInvalidRegion(stack_frame, SystemModules);

			if (!flag && flag != ERROR)
			{
				DbgPrint("RIP was executing in invalid region: %llx\n", stack_frame);
			}

		}
	}

	return STATUS_SUCCESS;
}

BOOLEAN NmiCallback(_In_ PVOID Context, _In_ BOOLEAN Handled)
{
	//TODO need to implement context so we can check if nmis have been disabled
	UNREFERENCED_PARAMETER(Handled);

	ULONG proc_num = KeGetCurrentProcessorNumber();

	//Cannot allocate pool in this function as it runs at IRQL >= dispatch level
	//so ive just allocated a global pool with size equal to 0x200 * num_procs

	int num_frames_captured = RtlCaptureStackBackTrace(
		0,
		0x200,
		(uintptr_t)stack_frames + proc_num * 0x200,
		NULL
	);

	PVOID current_thread = KeGetCurrentThread();

	NMI_CALLBACK_DATA thread_data = { 0 };
	thread_data.kthread_address = (UINT64)current_thread;
	thread_data.kprocess_address = (UINT64)PsGetCurrentProcess();
	thread_data.stack_base = *((UINT64*)((uintptr_t)current_thread + 0x030));
	thread_data.stack_limit = *((UINT64*)((uintptr_t)current_thread + 0x038));
	thread_data.start_address = *((UINT64*)((uintptr_t)current_thread + 0x450));		//can be spoofed but still a decent detection vector
	thread_data.cr3 = __readcr3();
	thread_data.stack_frames_offset = proc_num * 0x200;
	thread_data.num_frames_captured = num_frames_captured;

	RtlCopyMemory(
		((uintptr_t)thread_data_pool) + proc_num * sizeof(thread_data),
		&thread_data,
		sizeof(thread_data)
	);

	PNMI_CONTEXT context = (PNMI_CONTEXT)((uintptr_t)Context + proc_num * sizeof(NMI_CONTEXT));
	context->nmi_callbacks_run += 1;

	DbgPrint("num nmis called: %i from addr: %llx", context->nmi_callbacks_run, (uintptr_t)context);

	return TRUE;
}

NTSTATUS LaunchNonMaskableInterrupt(_In_ ULONG NumCores)
{
	//Allocate a pool for our Processor affinity structures
	PKAFFINITY_EX ProcAffinityPool = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAFFINITY_EX), NMI_CB_POOL_TAG);

	if (!ProcAffinityPool)
		return STATUS_ABANDONED;

	stack_frames = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumCores * 0x200, NMI_CB_POOL_TAG);

	if (!stack_frames)
		return STATUS_ABANDONED;

	thread_data_pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumCores * sizeof(NMI_CALLBACK_DATA), NMI_CB_POOL_TAG);

	if (!thread_data_pool)
		return STATUS_ABANDONED;

	//Calculate our delay (200ms currently)
	LARGE_INTEGER delay = { 0 };
	delay.QuadPart -= 200 * 10000;

	//Iterate over each logical processor to fire NMI
	for (ULONG core = 0; core < NumCores; core++)
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

	ExFreePoolWithTag(ProcAffinityPool, NMI_CB_POOL_TAG);

	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("unloading driver");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	DriverObject->DriverUnload = DriverUnload;

	//Count cores (NMI's are sent per core)
	ULONG num_cores = KeQueryActiveProcessorCountEx(0);

	nmi_context = ExAllocatePool2(POOL_FLAG_NON_PAGED, num_cores * sizeof(NMI_CONTEXT), NMI_CB_POOL_TAG);

	if (!nmi_context)
		return STATUS_ABANDONED;

	//Register our callback
	PVOID NMICallbackHandle = KeRegisterNmiCallback(NmiCallback, nmi_context);

	if (!NMICallbackHandle)
		return STATUS_ABANDONED;

	if (!NT_SUCCESS(LaunchNonMaskableInterrupt(num_cores)))
	{
		DbgPrint("Failed to launch NMI");
		return STATUS_FAILED_DRIVER_ENTRY;
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

	PINVALID_DRIVERS_HEAD head =
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVERS_HEAD), NMI_CB_POOL_TAG);

	if (!head)
		return STATUS_ABANDONED;

	InitDriverList(head);

	if (!NT_SUCCESS(ValidateDriverObjects(&modules, head)))
	{
		DbgPrint("Failed to validate driver objects");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	if (head->count > 0)
	{
		DbgPrint("found INVALID drivers with count: %i\n", head->count);
		EnumerateInvalidDrivers(head);

		for (int i = 0; i < head->count; i++)
		{
			RemoveInvalidDriverFromList(head);
		}
	}
	else
	{
		DbgPrint("No INVALID drivers found\n");
	}

	//Unregister our callback + free pools
	KeDeregisterNmiCallback(NMICallbackHandle);

	ExFreePoolWithTag(nmi_context, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(stack_frames, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(head, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(modules.address, NMI_CB_POOL_TAG);
	ExFreePoolWithTag(thread_data_pool, NMI_CB_POOL_TAG);

	return STATUS_SUCCESS;
}
