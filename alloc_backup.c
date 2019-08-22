#include <stdint.h>
#include <stdlib.h>
#include <string.h>


extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

#ifndef __DEBUG
#define debug(...) {}
#endif

unsigned int max_size;

void *myalloc(size_t size)
{
    void *p = sbrk(size);
    debug("alloc(%u): %p\n", (unsigned int)size, p);
    max_size += size;
    debug("max: %u\n", max_size);
    return p;
}

void *myrealloc(void *ptr, size_t size)
{
    void *p = NULL;
    if (size != 0)
    {
        p = sbrk(size);
        if (ptr)
            memcpy(p, ptr, size);
        max_size += size;
        debug("max: %u\n", max_size);
    }
    debug("realloc(%p, %u): %p\n", ptr, (unsigned int)size, p);
    return p;
}

void myfree(void *ptr)
{
    debug("free(%p)\n", ptr);
}
