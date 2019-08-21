/**
 * balloc implementation
 * 
 * Very very dumb allocator
 **/


#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

#define DEBUG(msg)      debug("%s: %s\n", __func__, msg)

typedef struct memory_chunk {
    uint32_t unused;
    size_t size;
    struct memory_chunk *next;
    struct memory_chunk *prev;
} memory_chunk;

typedef struct balloc_info_struct {
    void *uninitialized_arena;
    void *end_of_arena;

    void *
} balloc_info_struct;

static balloc_info_struct balloc_info = {NULL, NULL};

// Define consts
#define SBRK_SIZE_ALLIGN            12
#define ALLOC_SIZE_ALLIGN           3

#define MIN_ALLOC_SIZE              sizeof(memory_chunk)
#define HEADER_SIZE                 offsetof(memory_chunk, next)
#define UNINITIALIZED_ARENA_SIZE    (balloc_info.end_of_arena - balloc_info.uninitialized_arena)

// Define macro functions
#define CHECK_PREV_INUSE(chunk)          ((chunk)->size & 0x1)
#define SET_PREV_INUSE(chunk)            ((chunk)->size |= 0x1)

#define GET_LEAST_ALLOC_SIZE_MULTIPLES(size, multiples)     ((((size) + (multiples) - 1) / (multiples)) * (multiples))
#define GET_ALLIGNED_ALLOC_SIZE_SHIFT(size, shift)             ((((size) + (1 << (shift)) - 1) >> (shift)) << (shift))

/**
 * Increase arena size enough to hold [size] bytes. 
 * Alligns break address by ALLOC_SIZE_ALLIGN. 
 * arguments:
 *      size_t size:
 *          minimum bytes needed. 
 * returns:
 *      true on success, false on failure. 
 **/
bool increase_arena(size_t size) {
    if(UNINITIALIZED_ARENA_SIZE >= size) {
        DEBUG("size should not be greater than UNINITIALIZED_ARENA_SIZE. Something wrong. ");
    }
    size_t size_to_sbrk = GET_ALLIGNED_ALLOC_SIZE_SHIFT(size, SBRK_SIZE_ALLIGN);
    debug("size_to_sbrk: 0x%x\n", size_to_sbrk);
    void *p = sbrk(size_to_sbrk);
    if(p == -1) {
        DEBUG("sbrk 1");
        return false;
    }
    if(balloc_info.uninitialized_arena == 0) {
        balloc_info.uninitialized_arena = p;
        debug("%p\n", balloc_info.uninitialized_arena);
    }
    balloc_info.end_of_arena = sbrk(0);
    return true;
}


/**
 * Alloc memory_chunk on uninitialized area. If size of uninitialized_arena is not enough, call increase_arena. 
 * returns:
 *      
 **/
void *dumb_alloc(size_t size) {
    size_t alloc_size = GET_ALLIGNED_ALLOC_SIZE_SHIFT(size + HEADER_SIZE, ALLOC_SIZE_ALLIGN);
    if(alloc_size < size + HEADER_SIZE) {
        exit(1);
    }
    
    if(UNINITIALIZED_ARENA_SIZE < alloc_size)
        if(!increase_arena(alloc_size))
            return NULL;   
    
    memory_chunk *mchunkptr = balloc_info.uninitialized_arena;
    debug("%p\n", mchunkptr);
    mchunkptr->size = alloc_size;
    SET_PREV_INUSE(mchunkptr);
    balloc_info.uninitialized_arena += alloc_size;
    return mchunkptr;
}

void *myalloc(size_t size) {
    if(balloc_info.uninitialized_arena == NULL)
        if(!increase_arena(GET_ALLIGNED_ALLOC_SIZE_SHIFT(size + HEADER_SIZE, ALLOC_SIZE_ALLIGN)))
            return NULL;
    return dumb_alloc(size);
}

void *myrealloc(void *ptr, size_t size) {
    if(balloc_info.uninitialized_arena == NULL)
        if(!increase_arena(GET_ALLIGNED_ALLOC_SIZE_SHIFT(size + HEADER_SIZE, ALLOC_SIZE_ALLIGN)))
            return NULL;
    void *newptr = NULL;
    newptr = dumb_alloc(size);
    if(ptr != NULL)
        memcpy(newptr, ptr, size);
    return newptr;
}

void myfree(void *ptr) {
    if(ptr == NULL)
        return;
    
}
