#include "driver.h"

#include "ia32.h"

#define IOCTL_RUN_NMI_CALLBACKS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _NMI_CONTEXT
{
        UINT64  interrupted_rip;
        UINT64  interrupted_rsp;
        UINT32  callback_count;
        BOOLEAN user_thread;

} NMI_CONTEXT, *PNMI_CONTEXT;

VOID
InitDriverList(_In_ PINVALID_DRIVERS_HEAD ListHead)
{
        ListHead->count       = 0;
        ListHead->first_entry = NULL;
}

VOID
AddDriverToList(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead, _In_ PDRIVER_OBJECT Driver)
{
        PINVALID_DRIVER new_entry = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVER), INVALID_DRIVER_LIST_ENTRY_POOL);

        if (!new_entry)
                return;

        new_entry->driver               = Driver;
        new_entry->next                 = InvalidDriversHead->first_entry;
        InvalidDriversHead->first_entry = new_entry;
}

VOID
RemoveInvalidDriverFromList(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead)
{
        if (InvalidDriversHead->first_entry)
        {
                PINVALID_DRIVER entry           = InvalidDriversHead->first_entry;
                InvalidDriversHead->first_entry = InvalidDriversHead->first_entry->next;
                ExFreePoolWithTag(entry, INVALID_DRIVER_LIST_ENTRY_POOL);
        }
}

VOID
EnumerateInvalidDrivers(_In_ PINVALID_DRIVERS_HEAD InvalidDriversHead)
{
        PINVALID_DRIVER entry = InvalidDriversHead->first_entry;

        while (entry != NULL)
        {
                DEBUG_LOG("Invalid Driver: %wZ", entry->driver->DriverName);
                entry = entry->next;
        }
}

NTSTATUS
ValidateDriverObjectHasBackingModule(_In_ PSYSTEM_MODULES ModuleInformation,
                                     _In_ PDRIVER_OBJECT  DriverObject,
                                     _Out_ PBOOLEAN       Result)
{
        if (!ModuleInformation || !DriverObject || !Result)
                return STATUS_INVALID_PARAMETER;

        for (INT i = 0; i < ModuleInformation->module_count; i++)
        {
                PRTL_MODULE_EXTENDED_INFO system_module =
                    (PRTL_MODULE_EXTENDED_INFO)((uintptr_t)ModuleInformation->address +
                                                i * sizeof(RTL_MODULE_EXTENDED_INFO));

                if (system_module->ImageBase == DriverObject->DriverStart)
                {
                        *Result = TRUE;
                        return STATUS_SUCCESS;
                }
        }

        DEBUG_LOG("invalid driver found");
        *Result = FALSE;

        return STATUS_SUCCESS;
}

// https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-3-4a0e195d947b
NTSTATUS
GetSystemModuleInformation(_Out_ PSYSTEM_MODULES ModuleInformation)
{
        if (!ModuleInformation)
                return STATUS_INVALID_PARAMETER;

        ULONG size = 0;

        /*
         * query system module information without an output buffer to get
         * number of bytes required to store all module info structures
         */
        if (!NT_SUCCESS(RtlQueryModuleInformation(&size, sizeof(RTL_MODULE_EXTENDED_INFO), NULL)))
        {
                DEBUG_ERROR("Failed to query module information");
                return STATUS_ABANDONED;
        }

        /* Allocate a pool equal to the output size of RtlQueryModuleInformation */
        PRTL_MODULE_EXTENDED_INFO driver_information =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, size, SYSTEM_MODULES_POOL);

        if (!driver_information)
        {
                DEBUG_ERROR("Failed to allocate pool LOL");
                return STATUS_ABANDONED;
        }

        /* Query the modules again this time passing a pointer to the allocated buffer */
        if (!NT_SUCCESS(RtlQueryModuleInformation(
                &size, sizeof(RTL_MODULE_EXTENDED_INFO), driver_information)))
        {
                DEBUG_ERROR("Failed lolz");
                ExFreePoolWithTag(driver_information, SYSTEM_MODULES_POOL);
                return STATUS_ABANDONED;
        }

        ModuleInformation->address      = driver_information;
        ModuleInformation->module_count = size / sizeof(RTL_MODULE_EXTENDED_INFO);

        return STATUS_SUCCESS;
}

NTSTATUS
ValidateDriverObjects(_In_ PSYSTEM_MODULES       SystemModules,
                      _In_ PINVALID_DRIVERS_HEAD InvalidDriverListHead)
{
        if (!SystemModules || !InvalidDriverListHead)
                return STATUS_INVALID_PARAMETER;

        HANDLE            handle;
        OBJECT_ATTRIBUTES attributes = {0};
        PVOID             directory  = {0};
        UNICODE_STRING    directory_name;

        RtlInitUnicodeString(&directory_name, L"\\Driver");

        InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes)))
        {
                DEBUG_ERROR("Failed to query directory object");
                return STATUS_ABANDONED;
        }

        if (!NT_SUCCESS(ObReferenceObjectByHandle(
                handle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, &directory, NULL)))
        {
                DEBUG_ERROR("Failed to reference directory by handle");
                ZwClose(handle);
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

        ExAcquirePushLockExclusiveEx(&directory_object->Lock, NULL);

        for (INT i = 0; i < NUMBER_HASH_BUCKETS; i++)
        {
                POBJECT_DIRECTORY_ENTRY entry = directory_object->HashBuckets[i];

                if (!entry)
                        continue;

                POBJECT_DIRECTORY_ENTRY sub_entry = entry;

                while (sub_entry)
                {
                        PDRIVER_OBJECT current_driver = sub_entry->Object;
                        BOOLEAN        flag;

                        if (!NT_SUCCESS(ValidateDriverObjectHasBackingModule(
                                SystemModules, current_driver, &flag)))
                        {
                                DEBUG_LOG("Error validating driver object");
                                ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
                                ObDereferenceObject(directory);
                                ZwClose(handle);
                                return STATUS_ABANDONED;
                        }

                        if (!flag)
                        {
                                InvalidDriverListHead->count += 1;
                                AddDriverToList(InvalidDriverListHead, current_driver);
                        }

                        sub_entry = sub_entry->ChainLink;
                }
        }

        ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
        ObDereferenceObject(directory);
        ZwClose(handle);

        return STATUS_SUCCESS;
}

NTSTATUS
IsInstructionPointerInInvalidRegion(_In_ UINT64          RIP,
                                    _In_ PSYSTEM_MODULES SystemModules,
                                    _Out_ PBOOLEAN       Result)
{
        if (!RIP || !SystemModules || !Result)
                return STATUS_INVALID_PARAMETER;

        /* Note that this does not check for HAL or PatchGuard Execution */
        for (INT i = 0; i < SystemModules->module_count; i++)
        {
                PRTL_MODULE_EXTENDED_INFO system_module =
                    (PRTL_MODULE_EXTENDED_INFO)((uintptr_t)SystemModules->address +
                                                i * sizeof(RTL_MODULE_EXTENDED_INFO));

                UINT64 base = (UINT64)system_module->ImageBase;
                UINT64 end  = base + system_module->ImageSize;

                if (RIP >= base && RIP <= end)
                {
                        *Result = TRUE;
                        return STATUS_SUCCESS;
                }
        }

        *Result = FALSE;
        return STATUS_SUCCESS;
}

NTSTATUS
AnalyseNmiData(_In_ PNMI_CONTEXT NmiContext, _In_ PSYSTEM_MODULES SystemModules)
{
        if (!NmiContext || !SystemModules)
                return STATUS_INVALID_PARAMETER;

        BOOLEAN flag = FALSE;

        for (INT core = 0; core < KeQueryActiveProcessorCount(0); core++)
        {
                /* Make sure our NMIs were run  */
                if (!NmiContext[core].callback_count)
                {
                        DEBUG_LOG("no nmi callbacks were run, nmis potentially disabled");
                        return STATUS_SUCCESS;
                }

                if (NmiContext[core].user_thread)
                        continue;

                if (!NT_SUCCESS(IsInstructionPointerInInvalidRegion(
                        NmiContext[core].interrupted_rip, SystemModules, &flag)))
                {
                        DEBUG_ERROR("errro checking RIP for current stack address");
                        continue;
                }

                flag == TRUE ? DEBUG_LOG("RIP: %llx was xecuting within valid module",
                                         NmiContext[core].interrupted_rip)
                             : DEBUG_ERROR("RIP %llx was executing in INVALID MEMORY",
                                           NmiContext[core].interrupted_rip);
        }

        return STATUS_SUCCESS;
}

#define IA32_GS_BASE                 0xc0000101
#define KPCR_TSS_BASE_OFFSET         0x008
#define TSS_IST_OFFSET               0x01c
#define WINDOWS_USERMODE_MAX_ADDRESS 0x00007FFFFFFFFFFF

typedef struct _MACHINE_FRAME
{
        UINT64 rip;
        UINT64 cs;
        UINT64 eflags;
        UINT64 rsp;
        UINT64 ss;

} MACHINE_FRAME, *PMACHINE_FRAME;

BOOLEAN
NmiCallback(_In_ PVOID Context, _In_ BOOLEAN Handled)
{
        UNREFERENCED_PARAMETER(Handled);

        PNMI_CONTEXT           nmi_context   = (PNMI_CONTEXT)Context;
        ULONG                  proc_num      = KeGetCurrentProcessorNumber();
        UINT64                 kpcr          = 0;
        TASK_STATE_SEGMENT_64* tss           = NULL;
        PMACHINE_FRAME         machine_frame = NULL;

        /*
         * To find the IRETQ frame (MACHINE_FRAME) we need to find the top of the NMI ISR stack.
         * This is stored at TSS->Ist[3]. To find the TSS, we can read it from KPCR->TSS_BASE. Once
         * we have our TSS, we can read the value at TSS->Ist[3] which points to the top of the ISR
         * stack, and subtract the size of the MACHINE_FRAME struct. Allowing us read the
         * interrupted RIP.
         */
        kpcr          = __readmsr(IA32_GS_BASE);
        tss           = *(TASK_STATE_SEGMENT_64**)(kpcr + KPCR_TSS_BASE_OFFSET);
        machine_frame = tss->Ist3 - sizeof(MACHINE_FRAME);

        if (machine_frame->rip <= WINDOWS_USERMODE_MAX_ADDRESS)
                nmi_context[proc_num].user_thread = TRUE;

        nmi_context[proc_num].interrupted_rip = machine_frame->rip;
        nmi_context[proc_num].interrupted_rsp = machine_frame->rsp;
        nmi_context[proc_num].callback_count += 1;

        DEBUG_LOG("[NMI CALLBACK]: Core Number: %lx, Interrupted RIP: %llx, Interrupted RSP: %llx",
                  proc_num,
                  machine_frame->rip,
                  machine_frame->rsp);

        return TRUE;
}

NTSTATUS
LaunchNonMaskableInterrupt(_In_ PNMI_CONTEXT NmiContext)
{
        if (!NmiContext)
                return STATUS_INVALID_PARAMETER;

        PKAFFINITY_EX ProcAffinityPool =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAFFINITY_EX), PROC_AFFINITY_POOL);

        if (!ProcAffinityPool)
                return STATUS_MEMORY_NOT_ALLOCATED;

        PVOID registration_handle = KeRegisterNmiCallback(NmiCallback, NmiContext);

        if (!registration_handle)
        {
                ExFreePoolWithTag(ProcAffinityPool, PROC_AFFINITY_POOL);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        LARGE_INTEGER delay = {0};
        delay.QuadPart -= 100 * 10000;

        for (ULONG core = 0; core < KeQueryActiveProcessorCount(0); core++)
        {
                KeInitializeAffinityEx(ProcAffinityPool);
                KeAddProcessorAffinityEx(ProcAffinityPool, core);

                DEBUG_LOG("Sending NMI");
                HalSendNMI(ProcAffinityPool);

                /*
                 * Only a single NMI can be active at any given time, so arbitrarily
                 * delay execution  to allow time for the NMI to be processed
                 */
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }

        KeDeregisterNmiCallback(registration_handle);
        ExFreePoolWithTag(ProcAffinityPool, PROC_AFFINITY_POOL);

        return STATUS_SUCCESS;
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
        UNREFERENCED_PARAMETER(DriverObject);
        DEBUG_LOG("unloading driver");
}

NTSTATUS
DriverCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(DeviceObject);
        DEBUG_LOG("Handle to device opened");
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
}

NTSTATUS
DriverClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(DeviceObject);
        DEBUG_LOG("Handle to device closed");
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
}

NTSTATUS
HandleNmiIOCTL()
{
        NTSTATUS       status         = STATUS_SUCCESS;
        SYSTEM_MODULES system_modules = {0};
        PNMI_CONTEXT   nmi_context    = NULL;

        nmi_context = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                      KeQueryActiveProcessorCount(0) * sizeof(NMI_CONTEXT),
                                      NMI_CONTEXT_POOL);

        if (!nmi_context)
                return STATUS_MEMORY_NOT_ALLOCATED;

        /*
         * We query the system modules each time since they can potentially
         * change at any time
         */
        status = GetSystemModuleInformation(&system_modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("Error retriving system module information");
                return status;
        }

        status = LaunchNonMaskableInterrupt(nmi_context);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("Error running NMI callbacks");
                ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
                ExFreePoolWithTag(nmi_context, NMI_CONTEXT_POOL);
                return status;
        }

        status = AnalyseNmiData(nmi_context, &system_modules);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("Error analysing nmi data");

        ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
        ExFreePoolWithTag(nmi_context, NMI_CONTEXT_POOL);

        return status;
}

NTSTATUS
HandleValidateDriversIOCTL()
{
        NTSTATUS       status         = STATUS_SUCCESS;
        SYSTEM_MODULES system_modules = {0};

        /* Fix annoying visual studio linting error */
        RtlZeroMemory(&system_modules, sizeof(SYSTEM_MODULES));

        status = GetSystemModuleInformation(&system_modules);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("Error retriving system module information");
                return status;
        }

        PINVALID_DRIVERS_HEAD head = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(INVALID_DRIVERS_HEAD), INVALID_DRIVER_LIST_HEAD_POOL);

        if (!head)
        {
                ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
                return STATUS_ABANDONED;
        }

        /*
         * Use a linked list here so that so we have easy access to the invalid drivers
         * which we can then use to copy the drivers logic for further analysis in
         * identifying drivers specifically used for the purpose of cheating
         */

        InitDriverList(head);

        if (!NT_SUCCESS(ValidateDriverObjects(&system_modules, head)))
        {
                DEBUG_ERROR("Failed to validate driver objects");
                ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
                return STATUS_ABANDONED;
        }

        if (head->count > 0)
        {
                DEBUG_LOG("found INVALID drivers with count: %i", head->count);
                EnumerateInvalidDrivers(head);

                for (INT i = 0; i < head->count; i++)
                {
                        RemoveInvalidDriverFromList(head);
                }
        }
        else
        {
                DEBUG_LOG("No INVALID drivers found :)");
        }

        ExFreePoolWithTag(head, INVALID_DRIVER_LIST_HEAD_POOL);
        ExFreePoolWithTag(system_modules.address, SYSTEM_MODULES_POOL);
        return status;
}

NTSTATUS
MajorControl(_In_ PDRIVER_OBJECT DriverObject, _In_ PIRP Irp)
{
        UNREFERENCED_PARAMETER(DriverObject);

        NTSTATUS           status         = STATUS_SUCCESS;
        PIO_STACK_LOCATION stack_location = IoGetCurrentIrpStackLocation(Irp);
        HANDLE             handle;

        switch (stack_location->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_RUN_NMI_CALLBACKS:
                DEBUG_LOG("IOCTL_RUN_NMI_CALLBACKS Received");

                status = HandleNmiIOCTL();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("Failed to handle NMI IOCTL");

                break;

        case IOCTL_VALIDATE_DRIVER_OBJECTS:
                DEBUG_LOG("IOCTL_VALIDATE_DRIVER_OBJECTS Received");

                /*
                 * The reason this function is run in a new thread and not the thread
                 * issuing the IOCTL is because ZwOpenDirectoryObject issues a
                 * user mode handle if called on the user mode thread calling DeviceIoControl.
                 * This is a problem because when we pass said handle ObReferenceObjectByHandle
                 * it will issue a bug check under windows driver verifier.
                 */

                status = PsCreateSystemThread(&handle,
                                              PROCESS_ALL_ACCESS,
                                              NULL,
                                              NULL,
                                              NULL,
                                              HandleValidateDriversIOCTL,
                                              NULL);

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("Failed to start thread to validate system drivers");

                break;

        default: DEBUG_ERROR("Invalid IOCTl code passed"); break;
        }

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
        UNREFERENCED_PARAMETER(RegistryPath);

        NTSTATUS status    = STATUS_SUCCESS;
        ULONG    num_cores = KeQueryActiveProcessorCountEx(0);

        status = IoCreateDevice(DriverObject,
                                0,
                                &DEVICE_NAME,
                                FILE_DEVICE_UNKNOWN,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE,
                                &DriverObject->DeviceObject);

        if (!NT_SUCCESS(status))
                return status;

        status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_LINK, &DEVICE_NAME);

        if (!NT_SUCCESS(status))
        {
                IoDeleteDevice(&DriverObject->DeviceObject);
                return status;
        }

        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MajorControl;
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DriverCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DriverClose;
        DriverObject->DriverUnload                         = DriverUnload;

        return status;
}