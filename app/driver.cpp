#include "driver.h"

DriverInterface::DriverInterface( LPCWSTR DeviceName )
{
	if ( !DeviceName )
	{
		std::cout << "Invalid device name passed as argument" << std::endl;
		return;
	}

	this->device_name = DeviceName;
	this->status = FALSE;

	device_handle = CreateFileW(
		DeviceName,
		GENERIC_WRITE | GENERIC_READ | GENERIC_EXECUTE,
		0,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
		0
	);

	if ( !device_handle )
	{
		std::cout << "Failed to open handle to device" << std::endl;
		return;
	}
}

bool DriverInterface::RunNmiCallbacks()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_RUN_NMI_CALLBACKS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		( LPOVERLAPPED )NULL
	);

	return status;
}

bool DriverInterface::ValidateDriverObjects()
{
	status = DeviceIoControl(
		device_handle,
		IOCTL_VALIDATE_DRIVER_OBJECTS,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		( LPOVERLAPPED )NULL
	);

	return status;
}


