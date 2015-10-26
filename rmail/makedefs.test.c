#include <stdlib.h>
#include <stdio.h>
int     main(void)
{
    printf("%s\n", DEF_SHLIB_DIR);
    fflush(stdout);
    exit(ferror(stdout) ? 1 : 0);
}
