# NMI Callback Handler

simple project to demonstrate how NMIs can be used to stackwalk. will probs expand to include other detection vectors like start address etc.

Finds the `MACHINE_FRAME` structure which represents how the `iretq` instruction returns from an isr to determine the rip that was interrupted by the NMI. 