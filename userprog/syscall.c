#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_number = f->R.rax; // system call number 가져오기
	switch (syscall_number){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rsi);
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}

void
check_address (void *addr){
	if (addr != NULL && is_user_vaddr(addr)){
		return; 	// 유효한 주소
	}
	exit(-1);		// 유효하지 않은 주소 처리(state = -1)
}
void
halt (void){
	power_off (); // pintos 완전히 종료
}
void
exit (int status){
	struct thread *curr = thread_current();
	curr->status = status;
	printf("%s(프로세스 이름): exit(%d)\n",curr->name, status); // process termination message
	ASSERT(curr->status == 0);
	thread_exit();
}