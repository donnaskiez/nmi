#include "driver.h"

#define IOCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _NMI_CORE_CONTEXT
{
	INT nmi_callbacks_run;

}NMI_CORE_CONTEXT, * PNMI_CORE_CONTEXT;

typedef struct _NMI_CONTEXT
{
	PVOID thread_data_pool;
	PVOID stack_frames;
	PVOID nmi_core_context;
	INT core_count;

}NMI_CONTEXT, * PNMI_CONTEXT;

VOID InitDriverList(
	_In_ PINVALID_DRIVERS_HEAD ListHead
)
{
	ListHead->count = 0;
	ListHead->first_entry = NULL;
}

VOID AddDriverToList(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead,
	_In_ PDRIVER_OBJECT Driver
)
{
	PINVALID_DRIVER new_entry = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof( INVALID_DRIVER ),
		INVALID_DRIVER_LIST_ENTRY_POOL
	);

	if ( !new_entry )
		return;

	new_entry->driver = Driver;
	new_entry->next = InvalidDriversHead->first_entry;
	InvalidDriversHead->first_entry = new_entry;
}

VOID RemoveInvalidDriverFromList(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead
)
{
	if ( InvalidDriversHead->first_entry )
	{
		PINVALID_DRIVER entry = InvalidDriversHead->first_entry;
		InvalidDriversHead->first_entry = InvalidDriversHead->first_entry->next;
		ExFreePoolWithTag( entry, INVALID_DRIVER_LIST_ENTRY_POOL );
	}
}

VOID EnumerateInvalidDrivers(
	_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead
)
{
	PINVALID_DRIVER entry = InvalidDriversHead->first_entry;

	while ( entry != NULL )
	{
		DEBUG_LOG( "Invalid Driver: %wZ", entry->driver->DriverName );
		entry = entry->next;
	}
}

NTSTATUS ValidateDriverObjectHasBackingModule(
	_In_ PSYSTEM_MODULES ModuleInformation,
	_In_ PDRIVER_OBJECT DriverObject,
	_Out_ PBOOLEAN Result
)
{
	if ( !ModuleInformation || !DriverObject || !Result )
		return STATUS_INVALID_PARAMETER;

	for ( INT i = 0; i < ModuleInformation->module_count; i++ )
	{
		PRTL_MODULE_EXTENDED_INFO system_module = ( PRTL_MODULE_EXTENDED_INFO )(
			( uintptr_t )ModuleInformation->address + i * sizeof( RTL_MODULE_EXTENDED_INFO ) );

		if ( system_module->ImageBase == DriverObject->DriverStart )
		{
			*Result = TRUE;
			return STATUS_SUCCESS;
		}
	}

	DEBUG_LOG( "invalid driver found" );
	*Result = FALSE;

	return STATUS_SUCCESS;
}

//https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-3-4a0e195d947b
NTSTATUS GetSystemModuleInformation( 
	_Out_ PSYSTEM_MODULES ModuleInformation 
)
{
	if ( !ModuleInformation )
		return STATUS_INVALID_PARAMETER;

	ULONG size = 0;

	/*
	* query system module information without an output buffer to get
	* number of bytes required to store all module info structures
	*/
	if ( !NT_SUCCESS( RtlQueryModuleInformation(
		&size,
		sizeof( RTL_MODULE_EXTENDED_INFO ),
		NULL
	) ) )
	{
		DEBUG_ERROR( "Failed to query module information" );
		return STATUS_ABANDONED;
	}

	/* Allocate a pool equal to the output size of RtlQueryModuleInformation */
	PRTL_MODULE_EXTENDED_INFO driver_information = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		size,
		SYSTEM_MODULES_POOL
	);

	if ( !driver_information )
	{
		DEBUG_ERROR( "Failed to allocate pool LOL" );
		return STATUS_ABANDONED;
	}

	/* Query the modules again this time passing a pointer to the allocated buffer */
	if ( !NT_SUCCESS( RtlQueryModuleInformation(
		&size,
		sizeof( RTL_MODULE_EXTENDED_INFO ),
		driver_information
	) ) )
	{
		DEBUG_ERROR( "Failed lolz" );
		ExFreePoolWithTag( driver_information, SYSTEM_MODULES_POOL );
		return STATUS_ABANDONED;
	}

	ModuleInformation->address = driver_information;
	ModuleInformation->module_count = size / sizeof( RTL_MODULE_EXTENDED_INFO );

	return STATUS_SUCCESS;
}

NTSTATUS ValidateDriverObjects(
	_In_ PSYSTEM_MODULES SystemModules,
	_In_ PINVALID_DRIVERS_HEAD InvalidDriverListHead
)
{
	if ( !SystemModules || !InvalidDriverListHead )
		return STATUS_INVALID_PARAMETER;

	HANDLE handle;
	OBJECT_ATTRIBUTES attributes = { 0 };
	PVOID directory = { 0 };
	UNICODE_STRING directory_name;

	RtlInitUnicodeString( &directory_name, L"\\Driver" );

	InitializeObjectAttributes(
		&attributes,
		&directory_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	if ( !NT_SUCCESS( ZwOpenDirectoryObject(
		&handle,
		DIRECTORY_ALL_ACCESS,
		&attributes
	) ) )
	{
		DEBUG_ERROR( "Failed to query directory object" );
		return STATUS_ABANDONED;
	}

	if ( !NT_SUCCESS( ObReferenceObjectByHandle(
		handle,
		DIRECTORY_ALL_ACCESS,
		NULL,
		KernelMode,
		&directory,
		NULL
	) ) )
	{
		DEBUG_ERROR( "Failed to reference directory by handle" );
		ZwClose( handle );
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

	POBJECT_DIRECTORY directory_object = ( POBJECT_DIRECTORY )directory;

	ExAcquirePushLockExclusiveEx( &directory_object->Lock, NULL );

	for ( INT i = 0; i < NUMBER_HASH_BUCKETS; i++ )
	{
		POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[ i ];

		if ( !entry )
			continue;

		POBJECT_DIRECTORY_ENTRY sub_entry = entry;

		while ( sub_entry )
		{
			PDRIVER_OBJECT current_driver = sub_entry->Object;
			BOOLEAN flag;

			if ( !NT_SUCCESS( ValidateDriverObjectHasBackingModule(
				SystemModules,
				current_driver,
				&flag
			) ) )
			{
				DEBUG_LOG( "Error validating driver object" );
				ExReleasePushLockExclusiveEx( &directory_object->Lock, 0 );
				ObDereferenceObject( directory );
				ZwClose( handle );
				return STATUS_ABANDONED;
			}

			if ( !flag )
			{
				InvalidDriverListHead->count += 1;
				AddDriverToList( InvalidDriverListHead, current_driver );
			}

			sub_entry = sub_entry->ChainLink;
		}
	}

	ExReleasePushLockExclusiveEx( &directory_object->Lock, 0 );
	ObDereferenceObject( directory );
	ZwClose( handle );

	return STATUS_SUCCESS;
}

NTSTATUS IsInstructionPointerInInvalidRegion(
	_In_ UINT64 RIP,
	_In_ PSYSTEM_MODULES SystemModules,
	_Out_ PBOOLEAN Result
)
{
	if ( !RIP || !SystemModules || !Result )
		return STATUS_INVALID_PARAMETER;

	/* Note that this does not check for HAL or PatchGuard Execution */
	for ( INT i = 0; i < SystemModules->module_count; i++ )
	{
		PRTL_MODULE_EXTENDED_INFO system_module = ( PRTL_MODULE_EXTENDED_INFO )(
			( uintptr_t )SystemModules->address + i * sizeof( RTL_MODULE_EXTENDED_INFO ) );

		UINT64 base = ( UINT64 )system_module->ImageBase;
		UINT64 end = base + system_module->ImageSize;

		if ( RIP >= base && RIP <= end )
		{
			*Result = TRUE;
			return STATUS_SUCCESS;;
		}
	}

	*Result = FALSE;
	return STATUS_SUCCESS;
}

NTSTATUS AnalyseNmiData(
	_In_ PNMI_CONTEXT NmiContext,
	_In_ PSYSTEM_MODULES SystemModules
)
{
	if ( !NmiContext || !SystemModules )
		return STATUS_INVALID_PARAMETER;

	for ( INT core = 0; core < NmiContext->core_count; core++ )
	{
		PNMI_CORE_CONTEXT context = ( PNMI_CORE_CONTEXT )( ( uintptr_t )NmiContext->nmi_core_context + core * sizeof( NMI_CORE_CONTEXT ) );

		/* Make sure our NMIs were run  */
		if ( !context->nmi_callbacks_run )
		{
			DEBUG_LOG( "no nmi callbacks were run, nmis potentially disabled" );
			return STATUS_SUCCESS;
		}

		PNMI_CALLBACK_DATA thread_data = ( PNMI_CALLBACK_DATA )(
			( uintptr_t )NmiContext->thread_data_pool + core * sizeof( NMI_CALLBACK_DATA ) );

		DEBUG_LOG( "cpu number: %i callback count: %i", core, context->nmi_callbacks_run );

		/* Walk the stack */
		for ( INT frame = 0; frame < thread_data->num_frames_captured; frame++ )
		{
			BOOLEAN flag;
			DWORD64 stack_frame = *( DWORD64* )( 
				( ( uintptr_t )NmiContext->stack_frames + thread_data->stack_frames_offset + frame * sizeof( PVOID ) ) );

			if ( !NT_SUCCESS( IsInstructionPointerInInvalidRegion( stack_frame, SystemModules, &flag ) ) )
			{
				DEBUG_ERROR( "errro checking RIP for current stack address" );
				continue;
			}

			flag == TRUE
				? DEBUG_LOG( "RIP: %llx was xecuting within valid module", stack_frame )
				: DEBUG_ERROR( "RIP %llx was executing in INVALID MEMORY", stack_frame );
		}
	}

	return STATUS_SUCCESS;
}

BOOLEAN NmiCallback(
	_In_ PVOID Context,
	_In_ BOOLEAN Handled
)
{
	UNREFERENCED_PARAMETER( Handled );

	PVOID current_thread = KeGetCurrentThread();
	NMI_CALLBACK_DATA thread_data = { 0 };
	PNMI_CONTEXT nmi_context = ( PNMI_CONTEXT )Context;
	ULONG proc_num = KeGetCurrentProcessorNumber();

	/* 
	* Cannot allocate pool in this function as it runs at IRQL >= dispatch level
	* so ive just allocated a global pool with size equal to 0x200 * num_procs
	*/
	INT num_frames_captured = RtlCaptureStackBackTrace(
		NULL,
		STACK_FRAME_POOL_SIZE,
		( uintptr_t )nmi_context->stack_frames + proc_num * STACK_FRAME_POOL_SIZE,
		NULL
	);

	/* 
	* This function is run in the context of the interrupted thread hence we can
	* gather any and all information regarding the thread that may be useful for analysis
	*/
	thread_data.kthread_address = ( UINT64 )current_thread;
	thread_data.kprocess_address = ( UINT64 )PsGetCurrentProcess();
	thread_data.stack_base = *( ( UINT64* )( ( uintptr_t )current_thread + KTHREAD_STACK_BASE_OFFSET ) );
	thread_data.stack_limit = *( ( UINT64* )( ( uintptr_t )current_thread + KTHREAD_STACK_LIMIT_OFFSET ) );
	thread_data.start_address = *( ( UINT64* )( ( uintptr_t )current_thread + KTHREAD_START_ADDRESS_OFFSET ) );
	thread_data.cr3 = __readcr3();
	thread_data.stack_frames_offset = proc_num * STACK_FRAME_POOL_SIZE;
	thread_data.num_frames_captured = num_frames_captured;

	RtlCopyMemory(
		( ( uintptr_t )nmi_context->thread_data_pool ) + proc_num * sizeof( thread_data ),
		&thread_data,
		sizeof( thread_data )
	);

	PNMI_CORE_CONTEXT core_context = 
		( PNMI_CORE_CONTEXT )( ( uintptr_t )nmi_context->nmi_core_context + proc_num * sizeof( NMI_CORE_CONTEXT ) );
	core_context->nmi_callbacks_run += 1;
	DEBUG_LOG( "core number: %lx, num nmis run: %i", proc_num, core_context->nmi_callbacks_run );

	return TRUE;
}

NTSTATUS LaunchNonMaskableInterrupt( 
	_In_ PNMI_CONTEXT NmiContext
)
{
	if ( !NmiContext )
		return STATUS_INVALID_PARAMETER;

	PKAFFINITY_EX ProcAffinityPool = 
		ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( KAFFINITY_EX ), PROC_AFFINITY_POOL );

	if ( !ProcAffinityPool )
		return STATUS_MEMORY_NOT_ALLOCATED;

	NmiContext->stack_frames = 
		ExAllocatePool2( POOL_FLAG_NON_PAGED, NmiContext->core_count * STACK_FRAME_POOL_SIZE, STACK_FRAMES_POOL );

	if ( !NmiContext->stack_frames )
	{
		ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	NmiContext->thread_data_pool = 
		ExAllocatePool2( POOL_FLAG_NON_PAGED, NmiContext->core_count * sizeof( NMI_CALLBACK_DATA ), THREAD_DATA_POOL );

	if ( !NmiContext->thread_data_pool )
	{
		ExFreePoolWithTag( NmiContext->stack_frames, STACK_FRAMES_POOL );
		ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	PVOID registration_handle = KeRegisterNmiCallback( NmiCallback, NmiContext );

	if ( !registration_handle )
	{
		ExFreePoolWithTag( NmiContext->thread_data_pool, THREAD_DATA_POOL );
		ExFreePoolWithTag( NmiContext->stack_frames, STACK_FRAMES_POOL );
		ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	LARGE_INTEGER delay = { 0 };
	delay.QuadPart -= 100 * 10000;

	for ( ULONG core = 0; core < NmiContext->core_count; core++ )
	{
		KeInitializeAffinityEx( ProcAffinityPool );
		KeAddProcessorAffinityEx( ProcAffinityPool, core );

		DEBUG_LOG( "Sending NMI" );
		HalSendNMI( ProcAffinityPool );

		/*
		* Only a single NMI can be active at any given time, so arbitrarily
		* delay execution  to allow time for the NMI to be processed
		*/
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
	}

	KeDeregisterNmiCallback( registration_handle );
	ExFreePoolWithTag( ProcAffinityPool, PROC_AFFINITY_POOL );

	return STATUS_SUCCESS;
}

VOID DriverUnload( 
	_In_ PDRIVER_OBJECT DriverObject 
)
{
	UNREFERENCED_PARAMETER( DriverObject );
	DEBUG_LOG( "unloading driver" );
}

NTSTATUS DriverCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER( DeviceObject );
	DEBUG_LOG( "Handle to device opened" );
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

NTSTATUS DriverClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER( DeviceObject );
	DEBUG_LOG( "Handle to device closed" );
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

NTSTATUS HandleNmiIOCTL()
{
	NTSTATUS status = STATUS_SUCCESS;
	SYSTEM_MODULES system_modules = { 0 };
	NMI_CONTEXT nmi_context = { 0 };

	nmi_context.core_count = KeQueryActiveProcessorCountEx( 0 );
	nmi_context.nmi_core_context = 
		ExAllocatePool2( POOL_FLAG_NON_PAGED, nmi_context.core_count * sizeof( NMI_CORE_CONTEXT ), NMI_CONTEXT_POOL );

	if ( !nmi_context.nmi_core_context )
		return STATUS_MEMORY_NOT_ALLOCATED;

	/*
	* We query the system modules each time since they can potentially
	* change at any time
	*/
	status = GetSystemModuleInformation( &system_modules );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Error retriving system module information" );
		return status;
	}

	status = LaunchNonMaskableInterrupt( &nmi_context );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Error running NMI callbacks" );
		ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
		ExFreePoolWithTag( nmi_context.nmi_core_context, NMI_CONTEXT_POOL );
		return status;
	}

	status = AnalyseNmiData( &nmi_context, &system_modules );

	if ( !NT_SUCCESS( status ) )
		DEBUG_ERROR( "Error analysing nmi data" );

	ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
	ExFreePoolWithTag( nmi_context.nmi_core_context, NMI_CONTEXT_POOL );

	if (nmi_context.stack_frames )
		ExFreePoolWithTag( nmi_context.stack_frames, STACK_FRAMES_POOL );
	if (nmi_context.thread_data_pool )
		ExFreePoolWithTag( nmi_context.thread_data_pool, THREAD_DATA_POOL );

	return status;
}

NTSTATUS HandleValidateDriversIOCTL()
{
	NTSTATUS status = STATUS_SUCCESS;
	SYSTEM_MODULES system_modules = { 0 };

	/* Fix annoying visual studio linting error */
	RtlZeroMemory( &system_modules, sizeof( SYSTEM_MODULES ) );

	status = GetSystemModuleInformation( &system_modules );

	if ( !NT_SUCCESS( status ) )
	{
		DEBUG_ERROR( "Error retriving system module information" );
		return status;
	}

	PINVALID_DRIVERS_HEAD head =
		ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( INVALID_DRIVERS_HEAD ), INVALID_DRIVER_LIST_HEAD_POOL );

	if ( !head )
	{
		ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
		return STATUS_ABANDONED;
	}

	/*
	* Use a linked list here so that so we have easy access to the invalid drivers
	* which we can then use to copy the drivers logic for further analysis in
	* identifying drivers specifically used for the purpose of cheating
	*/

	InitDriverList( head );

	if ( !NT_SUCCESS( ValidateDriverObjects( &system_modules, head ) ) )
	{
		DEBUG_ERROR( "Failed to validate driver objects" );
		ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
		return STATUS_ABANDONED;
	}

	if ( head->count > 0 )
	{
		DEBUG_LOG( "found INVALID drivers with count: %i", head->count );
		EnumerateInvalidDrivers( head );

		for ( INT i = 0; i < head->count; i++ )
		{ 
			RemoveInvalidDriverFromList( head ); 
		}
	}
	else
	{
		DEBUG_LOG( "No INVALID drivers found :)" );
	}

	ExFreePoolWithTag( head, INVALID_DRIVER_LIST_HEAD_POOL );
	ExFreePoolWithTag( system_modules.address, SYSTEM_MODULES_POOL );
	return status;
}

NTSTATUS MajorControl(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER( DriverObject );

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation( Irp );
	HANDLE handle;

	switch ( stack_location->Parameters.DeviceIoControl.IoControlCode )
	{
	case IOCTL_RUN_NMI_CALLBACKS:
		DEBUG_LOG( "IOCTL_RUN_NMI_CALLBACKS Received" );

		status = HandleNmiIOCTL();

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "Failed to handle NMI IOCTL" );

		break;

	case IOCTL_VALIDATE_DRIVER_OBJECTS:
		DEBUG_LOG( "IOCTL_VALIDATE_DRIVER_OBJECTS Received" );

		/*
		* The reason this function is run in a new thread and not the thread
		* issuing the IOCTL is because ZwOpenDirectoryObject issues a 
		* user mode handle if called on the user mode thread calling DeviceIoControl.
		* This is a problem because when we pass said handle ObReferenceObjectByHandle
		* it will issue a bug check under windows driver verifier.
		*/

		status = PsCreateSystemThread(
			&handle,
			PROCESS_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			HandleValidateDriversIOCTL,
			NULL
		);

		if ( !NT_SUCCESS( status ) )
			DEBUG_ERROR( "Failed to start thread to validate system drivers" );

		break;

	default:
		DEBUG_ERROR( "Invalid IOCTl code passed" );
		break;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER( RegistryPath );

	NTSTATUS status = STATUS_SUCCESS;
	ULONG num_cores = KeQueryActiveProcessorCountEx( 0 );

	status = IoCreateDevice(
		DriverObject,
		0,
		&DEVICE_NAME,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if ( !NT_SUCCESS( status ) )
		return status;

	status = IoCreateSymbolicLink( &DEVICE_SYMBOLIC_LINK, &DEVICE_NAME );

	if ( !NT_SUCCESS( status ) )
	{
		IoDeleteDevice( &DriverObject->DeviceObject );
		return status;
	}

	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = MajorControl;
	DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DriverCreate;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DriverClose;
	DriverObject->DriverUnload = DriverUnload;

	return status;
}