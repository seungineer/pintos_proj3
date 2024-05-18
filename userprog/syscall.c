#include "userprog/syscall.h"

#include <list.h>
#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

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

bool create(const char *file, unsigned initial_size);
void exit(int status);

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name);
int exec(const char *cmd_line);
int wait(int pid);

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void check_address(void *addr) {
    // if (addr != NULL && is_user_vaddr(addr)) {
    //     return;  // 유효한 주소
    // }
    // exit(-1);  // 유효하지 않은 주소 처리(state = -1)
    struct thread *t = thread_current();  // 변경사항
    /* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
    /* what if the user provides an invalid pointer, a pointer to kernel memory,
     * or a block partially in one of those regions */
    /* 잘못된 접근인 경우, 프로세스 종료 */
    if (!is_user_vaddr(addr) || addr == NULL)
        exit(-1);
    // pml4_get_page(t->pml4, addr) == NULL
}
void halt(void) {
    power_off();  // pintos 완전히 종료
}
void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", curr->name, status);  // process termination message
    // ASSERT(curr->status == 0);
    thread_exit();
}
bool create(const char *file, unsigned initial_size) {  // 파일 시스템 생성 시스템 콜
    check_address(file);                                // 유효한 주소인 경우
    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
    check_address(file);
    return filesys_remove(file);
}

int open(const char *file) {
    check_address(file);
    // lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);  // 파일을 오픈
    if (f == NULL)
        return -1;
    int fd = process_add_file(f);
    if (fd == -1)
        // file_close(f);
        free(f);
    // lock_release(&filesys_lock);
    return fd;
}
struct file *process_get_file(int fd) {
    // if (fd < 0 || fd >= FDT_COUNT_LIMIT)
    // 	return NULL;
    // struct file *f = thread_current()->fd_table[fd];
    // return f;
    // // 쓰레드 -> (이중 포인터) FD TABLE -> [X, X, PTR1, PTR2, PTR3, PTR4 ,....,][fd] => FD에 해당하는 포인터만 뽑아낸다.
    // // 뽑아낸 포인터가 가리키는 곳에 있는 FILE은 *f에 할당!
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    /* 파일 디스크립터에 해당하는 파일 객체를 리턴 */
    /* 없을 시 NULL 리턴 */
    if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        return NULL;

    return fdt[fd];
}

int filesize(int fd) {
    struct file *f = process_get_file(fd);  // fd를 이용해서 파일 객체 검색
    if (f == NULL)
        return -1;
    return file_length(f);
}

int exec(const char *cmd_line) {
    check_address(cmd_line);

    // process.c 파일의 process_create_initd 함수와 유사하다.
    // 단, 스레드를 새로 생성하는 건 fork에서 수행하므로
    // 이 함수에서는 새 스레드를 생성하지 않고 process_exec을 호출한다.

    // process_exec 함수 안에서 filename을 변경해야 하므로
    // 커널 메모리 공간에 cmd_line의 복사본을 만든다.
    // (현재는 const char* 형식이기 때문에 수정할 수 없다.)
    char *cmd_line_copy;
    cmd_line_copy = palloc_get_page(0);
    if (cmd_line_copy == NULL)
        exit(-1);                              // 메모리 할당 실패 시 status -1로 종료한다.
    strlcpy(cmd_line_copy, cmd_line, PGSIZE);  // cmd_line을 복사한다.

    // 스레드의 이름을 변경하지 않고 바로 실행한다.
    if (process_exec(cmd_line_copy) == -1)
        exit(-1);  // 실패 시 status -1로 종료한다.
}

int read(int fd, void *buffer, unsigned size)  // read 함수는 fd, size로 얼만큼 읽었는지 뱉어내는 함수
{
    // printf("fd 값 체크 : %d\n", fd);
    // printf("size 값 체크 : %d\n", size);
    check_address(buffer);
    // printf("=========read 시작=============\n");
    char *ptr = (char *)buffer;
    int bytes_read = 0;
    // printf("filesys_lock의 semaphoere : %d\n", *(&filesys_lock.semaphore.value));
    lock_acquire(&filesys_lock);  // 여기서 lock_aquire 함수 안을 갔다가 모두 실행되고, 페이지 폴트 발생함(0xfffffe8)
    // printf("=========read lock 요청=============\n");
    if (fd == STDIN_FILENO) {
        // printf("=========if문=============\n");

        for (int i = 0; i < size; i++) {
            /* 표준 입력(FD = 0)일 때 사용자가 입력한 데이터를 사용할 수 있도록 SIZE 만큼 처리 */
            *ptr++ = input_getc();
            bytes_read++;
        }
        lock_release(&filesys_lock);
    } else {
        // printf("=========else문=============\n");
        // printf("fd : %d\n", fd);
        if (fd < 2) {
            // printf("=========else문 > lock_release=============\n");
            lock_release(&filesys_lock);
            // printf("=========else문 > lock_release 탈출 =============\n");
            return -1;
        }
        struct thread *curr = thread_current();
        struct file **fdt = curr->fdt;
        /* 파일 디스크립터에 해당하는 파일 객체를 리턴 */
        /* 없을 시 NULL 리턴 */
        // if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        // 	struct file *file = NULL;
        // struct file *file = fdt[fd];

        struct file *file = process_get_file(fd);
        // printf("process_get_file 리턴 받음! %p\n", file);
        if (file == NULL) {
            // printf("리드1\n");
            // printf("=========file이 null일 때 > lock_release=============\n");
            lock_release(&filesys_lock);
            // printf("=========file이 null일 때 > lock_release 탈출 =============\n");
            return -1;
        }
        // printf("리드2\n");
        bytes_read = file_read(file, buffer, size);
        // printf("바이또 %d\n", bytes_read);
        lock_release(&filesys_lock);
    }
    // printf("=========안들어갔음=============\n");
    return bytes_read;
}

int write(int fd, const void *buffer, unsigned size) {
    check_address(buffer);
    int bytes_write = 0;
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        bytes_write = size;
    } else {
        if (fd < 2)
            return -1;
        struct file *file = process_get_file(fd);
        if (file == NULL)
            return -1;
        lock_acquire(&filesys_lock);
        bytes_write = file_write(file, buffer, size);
        lock_release(&filesys_lock);
    }
    return bytes_write;
}

void seek(int fd, unsigned position) {
    struct file *file = process_get_file(fd);
    if (file == NULL)
        return;
    file_seek(file, position);  // position에서 부터 file을 읽거나 쓰기 시작하도록 위치 지정
}

unsigned tell(int fd) {
    struct file *file = process_get_file(fd);
    if (file == NULL)
        return;
    return file_tell(file);
}
int wait(int pid) {
    return process_wait(pid);
}

void close(int fd) {
    // struct file *file = process_get_file(fd);
    // if (file == NULL)
    // 	return;
    // file_close(file); 		// 물리적으로 file이 사용한 리소스를 반환(해제)하는 함수
    // process_close_file(fd); // 프로세스에서 파일 디스크립터에 등록된 fd를 삭제해주는 함수

    struct thread *current = thread_current();
    if ((fd <= 1) || (current->next_fd <= fd))
        return;
    file_close(process_get_file(fd));
    current->fdt[fd] = NULL;
}

tid_t fork(const char *thread_name) {
    /* create new process, which is the clone of current process with the name THREAD_NAME*/
    struct thread *curr = thread_current();

    return process_fork(thread_name, &curr->parent_if);
    /* must return pid of the child process */
}
/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
    int syscall_number = f->R.rax;  // system call number 가져오기
    thread_current()->rsp_addr = f->rsp;
    switch (syscall_number) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            memcpy(&thread_current()->parent_if, f, sizeof(struct intr_frame));
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
            // case SYS_MMAP:
            // 	f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            // 	break;
            // case SYS_MUNMAP:
            // 	munmap(f->R.rdi);
            // 	break;
    }
    // printf ("system call!\n");
    // thread_exit ();
}
