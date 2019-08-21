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

#ifdef __DEBUG
#define DEBUG(msg)      debug("%s: %s\n", __func__, msg)
#define ASSERT(check, msg) {\
if((check)) {\
    debug("[ASSERT] %s: %s\n", __func__, msg);\
    exit(-1);\
}}
#else
#define DEBUG(msg) {}
#define ASSERT(check, msg) {}
#endif

typedef struct memory_chunk {
    // size of chunk, including header
    size_t size;
    // pointer to next free chunk
    // also overlaps userdata offset
    struct memory_chunk *next;
    struct memory_chunk *prev;
} memory_chunk;

typedef struct balloc_info_struct {
    void *uninitialized_arena;
    void *end_of_arena;
} balloc_info_struct;

static balloc_info_struct balloc_info = {NULL, NULL};

// Define consts
#define SBRK_SIZE_ALLIGN            12
#define ALLOC_SIZE_ALLIGN           3

#define MIN_ALLOC_SIZE              sizeof(memory_chunk)
#define HEADER_SIZE                 offsetof(memory_chunk, next)
#define UNINITIALIZED_ARENA_SIZE    (balloc_info.end_of_arena - balloc_info.uninitialized_arena)

// Define macro functions
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))


#define CHECK_PREV_INUSE(chunk)     ((chunk)->size & 0x1)
#define SET_PREV_INUSE(chunk)       ((chunk)->size |= 0x1)

#define GET_USERDATA_PTR(chunk)     (((void *)(chunk))+HEADER_SIZE)
#define GET_CHUNK_PTR(ptr)        (((void *)(ptr))-HEADER_SIZE)
#define GET_USERDATA_SIZE(chunk)    ((((chunk)->size) & (~((0x1 << ALLOC_SIZE_ALLIGN) - 1)))-HEADER_SIZE)
#define GET_CHUNK_SIZE(chunk)       (((chunk)->size) & (~((0x1 << ALLOC_SIZE_ALLIGN) - 1)))

#define GET_ALLIGNED_SIZE_MULTIPLES(size, multiples)        ((((size) + (multiples) - 1) / (multiples)) * (multiples))
#define GET_ALLIGNED_SIZE_SHIFT(size, shift)                ((((size) + (1 << (shift)) - 1) >> (shift)) << (shift))
#define GET_ALLIGNED_ALLOC_SIZE(size)                       MAX((GET_ALLIGNED_SIZE_SHIFT((size) + HEADER_SIZE, ALLOC_SIZE_ALLIGN)), GET_ALLIGNED_SIZE_SHIFT(MIN_ALLOC_SIZE, ALLOC_SIZE_ALLIGN))



/**
 * Increase arena size enough to hold [size] bytes. 
 * Alligns break address by SBRK_SIZE_ALLIGN. 
 * 
 * size_t size:
 *      minimum chunk size needed. 
 * returns:
 *      true on success, false on failure. 
 **/
bool increase_arena(size_t size) {
    ASSERT(UNINITIALIZED_ARENA_SIZE >= size, "UNINITIALIZED_ARENA_SIZE greater than size");
    size_t size_to_sbrk = GET_ALLIGNED_SIZE_SHIFT(size, SBRK_SIZE_ALLIGN);
    void *p = sbrk(size_to_sbrk);
    if(p == (void *)-1) {
        DEBUG("sbrk 1");
        return false;
    }
    if(balloc_info.uninitialized_arena == 0) {
        balloc_info.uninitialized_arena = p;
    }
    balloc_info.end_of_arena = sbrk(0);
    ASSERT(UNINITIALIZED_ARENA_SIZE < size, "smaller UNINITIALIZED_ARENA_SIZE");
    return true;
}


/**
 * Alloc memory_chunk on uninitialized area. If size of uninitialized_arena is not enough, call increase_arena. 
 *
 * size:
 *      minimum userdata size needed. 
 * returns:
 *      userdata pointer of memory_chunk. 
 **/
void *dumb_alloc(size_t size) {
    size_t alloc_size = GET_ALLIGNED_ALLOC_SIZE(size);
    ASSERT(alloc_size < size + HEADER_SIZE, "smaller alloc_size");
    ASSERT(alloc_size < MIN_ALLOC_SIZE, "smaller alloc_size");
    if(UNINITIALIZED_ARENA_SIZE < alloc_size)
        if(!increase_arena(alloc_size))
            return NULL;   
    
    memory_chunk *mchunkptr = balloc_info.uninitialized_arena;
    mchunkptr->size = alloc_size;
    SET_PREV_INUSE(mchunkptr);
    balloc_info.uninitialized_arena += alloc_size;
    ASSERT(GET_USERDATA_SIZE(mchunkptr) < size, "smaller userdata_size");
    ASSERT(GET_CHUNK_SIZE(mchunkptr) + (void *)mchunkptr != balloc_info.uninitialized_arena, "wrong size");
    return GET_USERDATA_PTR(mchunkptr);
}

/**
 * Alloc memory. 
 *
 * size:
 *      minimum userdata size needed. 
 * returns:
 *      userdata pointer of memory_chunk on success. NULL on fail.
 **/
void *myalloc(size_t size) {
    if(balloc_info.uninitialized_arena == NULL)
        if(!increase_arena(GET_ALLIGNED_ALLOC_SIZE(size)))
            return NULL;
    return dumb_alloc(size);
}

/**
 * Realloc memory. 
 *
 * ptr: 
 *      pointer to realloc. 
 * size:
 *      minimum userdata size needed. 
 * returns:
 *      userdata pointer of memory_chunk on success. NULL on fail.
 **/
void *myrealloc(void *ptr, size_t size) {
    if(ptr == NULL)
        return myalloc(size);

    memory_chunk *mchunkptr = GET_CHUNK_PTR(ptr);
    if(GET_USERDATA_SIZE(mchunkptr) >= size) {
        // TODO: decrease chunk size
        return ptr;
    }
    void *newptr = myalloc(size);
    if(ptr != NULL) {
        memcpy(newptr, ptr, GET_USERDATA_SIZE(mchunkptr));
    }

    return newptr;
}

/**
 * Free memory. 
 *
 * ptr: 
 *      pointer to free. 
 **/
void myfree(void *ptr) {
    if(ptr == NULL)
        return;
    // TODO: implement free
}
