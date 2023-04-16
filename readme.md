#NMI Callback Handler

This is a simple project with the goal of exploring what access a non maskable interrupt has to the currently executing thread that was interrupted. The end goal here is to stackwalk the interrupted thread to determine if any return addresses or the thread start address lies within invalid memory regions (manually mapped drivers etc.).