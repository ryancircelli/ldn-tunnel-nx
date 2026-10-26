.section .text.jmp, "ax", %progbits
.align 2

.global _start
_start:
	b __nx_rrt0_start
	.word __module_header - _start
	.ascii "HOMEBREW"

// A CPU exception re-enters the process here with x0 = exception type (non-zero) and
// x1 = the exception info (not -1), as libnx's crt0 checks. Dispatch before anything
// else: re-running relocation and the .bss clear would wipe the process and fault again
// (on locked memory such as transfer memory), hiding the original fault.
__nx_rrt0_start:
	cbz x0, __nx_rrt0_entry
	cmn x1, #1
	b.eq __nx_rrt0_entry
	b __nx_exception_dispatch
