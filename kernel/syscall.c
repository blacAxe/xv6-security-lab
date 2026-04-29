#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"


#define AUDIT_BUF_SIZE 2048
char audit_log_buffer[AUDIT_BUF_SIZE];
int audit_ptr = 0;

// Helper function to convert int to string manually in kernel
void itoa(int n, char s[]) {
    int i = 0;
    do { s[i++] = n % 10 + '0'; } while ((n /= 10) > 0);
    s[i] = '\0';
    // Reverse the string
    for (int j = 0, k = i-1; j < k; j++, k--) {
        char temp = s[j]; s[j] = s[k]; s[k] = temp;
    }
}

// Helper to keep the main function clean
void record_audit_raw(char *s) {
  while(*s && audit_ptr < AUDIT_BUF_SIZE - 1)
    audit_log_buffer[audit_ptr++] = *s++;
}

void record_audit(char *msg) {
  char time_str[16];
  extern uint ticks; // Access the global kernel clock
  
  itoa(ticks, time_str);
  
  if(audit_ptr + strlen(msg) + 20 >= AUDIT_BUF_SIZE) audit_ptr = 0;

  // Prepend [Time (T): X]
  record_audit_raw("[T:");
  record_audit_raw(time_str);
  record_audit_raw("] ");
  
  record_audit_raw(msg);
  audit_log_buffer[audit_ptr++] = '\n';
}

// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz) // both tests needed, in case of overflow
    return -1;
  if(copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  if(copyinstr(p->pagetable, buf, addr, max) < 0)
    return -1;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_pause(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);
extern uint64 sys_getaudit(void); // Added for silent audit 

// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_pause]   sys_pause,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_getaudit] sys_getaudit, // Added for silent audit
};

// A simple XOR checksum to detect kernel tampering
uint64
calculate_kernel_fingerprint() {
  uint64 fingerprint = 0;
  unsigned char *ptr = (unsigned char *)syscalls;
  for(int i = 0; i < 100; i++) {
    fingerprint ^= ptr[i];
  }
  return fingerprint;
}

void
syscall(void)
{
  int num;
  struct proc *p = myproc();
  char path[64]; // buffer to store the path for exec

  num = p->trapframe->a7;
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    // Use num to lookup the system call function for num, call it,
    // and store its return value in p->trapframe->a0

    // --- ONLY PRINT SENSITIVE CALLS TO SILENT AUDIT ---
    // Grab the path while it's still in memory (before the syscall potentially overwrites it)
    if(num == SYS_exec) {
      argstr(0, path, 64); 

      // CRITICAL CHECK: Catch them before they even start
      if(strncmp(path, "secret_tool", 11) == 0) {
        record_audit("[ALERT] Illegal Access Attempt! Killing Process.");
        p->killed = 1;
        p->trapframe->a0 = -1; // Return error to user
        return; 
      }
    }

    p->trapframe->a0 = syscalls[num]();

    // Log the results (using the the exact path we saved earlier)
    if(num == SYS_exec && p->pid > 2) {
      char sp_str[32];
      itoa(p->trapframe->sp, sp_str);

      uint64 integrity = calculate_kernel_fingerprint();
      char int_str[32];
      itoa(integrity, int_str);
      
      record_audit_raw("[SP: ");
      record_audit_raw(sp_str);
      record_audit_raw("] Executed: ");
      record_audit(path); // This uses the path grabbed in first step

      record_audit_raw("[INTEGRITY: ");
      record_audit_raw(int_str);
      record_audit_raw("] ");
    }
    // ----------------------------------

  } else {
    printf("%d %s: unknown sys call %d\n",
            p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
