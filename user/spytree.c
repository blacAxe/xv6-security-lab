#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(void) {
  char buf[2048];
  // The secret syscall to fetch the audit logs from the kernel
  int n = getaudit(buf); 
  
  if(n > 0) {
    printf("--- SECRET KERNEL AUDIT LOG ---\n");
    write(1, buf, n);
    printf("-------------------------------\n");
  } else {
    printf("No logs found.\n");
  }
  exit(0);
}