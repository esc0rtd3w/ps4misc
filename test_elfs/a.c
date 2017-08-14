void syscall(long int callnum, ...) {
   __asm__(
   "mov $0, %rax; syscall"
   );
}

#pragma weak    syscall2
extern int (*syscall2)(int rdi);


int main(int argc, char ** argv) {
    syscall(4, 1, "lol", 3);
    return 0;
}
