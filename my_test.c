#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "printf.h"

#define DEBUG 1

/* Exports from alloc.c */
void *myalloc(size_t size);
void *myrealloc(void *ptr, size_t size);
void myfree(void *ptr);

int main() {
	void *a, *b, *c, *d;
	printf("0x%p\n", a=myalloc(0x20));
	printf("0x%p\n", b=myalloc(0x20));
	printf("0x%p\n", c=myalloc(0x20));
	myfree(b);
	printf("0x%p\n", d=myalloc(0x20));
	return 0;

}

/* Debug printf support */
void _putchar(char character)
{
    write(STDERR_FILENO, &character, 1);
}

void debug(const char *fmt, ...)
{
#if DEBUG
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#endif
}
