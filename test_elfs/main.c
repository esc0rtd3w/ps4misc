#include "ps4base.h"
 
int main(void)
{
    //puts("This is a shared library test...");
    *(int*)&ps4syscall = 0;
    ps4syscall(0,0,0,0,0);
    return 0;
}
