#ifndef IDRIVER_H
#define IDRIVER_H

#include <windows.h>
#include <iostream>

#define IOCTL_RUN_NMI_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VALIDATE_DRIVER_OBJECTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2002, METHOD_BUFFERED, FILE_ANY_ACCESS)

class DriverInterface
{
	HANDLE device_handle;
	LPCWSTR device_name;
	BOOLEAN status;

public:

	DriverInterface( LPCWSTR DeviceName );

	bool RunNmiCallbacks();
	bool ValidateDriverObjects();

};

#endif // !IDRIVER_H
