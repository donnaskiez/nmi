#include "driver.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <chrono>
#include <thread>
#include <iostream>

#define LOG_INFO(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)

int main()
{
    LPCWSTR name = L"\\\\.\\nmi_handler";

    DriverInterface driver( name );

    LOG_INFO( "running nmi callbacks" );

    while ( true )
    {
        if ( !driver.ValidateDriverObjects() )
        {
            LOG_ERROR( "Failed to enable process load callbacks" );
            return ERROR;
        }

        LOG_INFO( "Successfully validated driver objects" );

        if ( !driver.RunNmiCallbacks() )
        {
            LOG_ERROR("failed to run nmi callbacks");
            return ERROR;      
        } 

        LOG_INFO( "Successfully run nmi callbacks" );

        std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
    }

    return 0;
}