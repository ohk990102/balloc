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


// Define consts
#define SBRK_SIZE_ALLIGN            (12)
#define ALLOC_SIZE_ALLIGN_SHIFT     (3)
#define ALLOC_SIZE_ALLIGN           (1 << ALLOC_SIZE_ALLIGN_SHIFT)

#define MIN_ALLOC_SIZE              (sizeof(memory_chunk))
#define HEADER_SIZE                 (offsetof(memory_chunk, next))
#define UNINITIALIZED_ARENA_SIZE    (balloc_info.end_of_arena - balloc_info.uninitialized_arena)

// Define macro functions
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define CHECK_FLAGS(chunk)          (((chunk)->size) & (ALLOC_SIZE_ALLIGN - 1))

#define CHECK_PREV_INUSE(chunk)     ((chunk)->size & 0x1)
#define SET_PREV_INUSE(chunk)       ((chunk)->size |= 0x1)

#define GET_USERDATA_PTR(chunk)     (((void *)(chunk))+offsetof(memory_chunk, next))
#define GET_CHUNK_PTR(ptr)          (((void *)(ptr))-offsetof(memory_chunk, next))
#define GET_USERDATA_SIZE(chunk)    ((((chunk)->size) & (~(ALLOC_SIZE_ALLIGN - 1)))-HEADER_SIZE)
#define GET_CHUNK_SIZE(chunk)       (((chunk)->size) & (~(ALLOC_SIZE_ALLIGN - 1)))

#define GET_ALLIGNED_SIZE_MULTIPLES(size, multiples)        ((((size) + (multiples) - 1) / (multiples)) * (multiples))
#define GET_ALLIGNED_SIZE_SHIFT(size, shift)                ((((size) + (1 << (shift)) - 1) >> (shift)) << (shift))
#define GET_ALLIGNED_ALLOC_SIZE(size)                       (MAX((GET_ALLIGNED_SIZE_SHIFT((size) + HEADER_SIZE, ALLOC_SIZE_ALLIGN_SHIFT)), GET_ALLIGNED_SIZE_SHIFT(MIN_ALLOC_SIZE, ALLOC_SIZE_ALLIGN_SHIFT)))

// Fastbin macros
#define FASTBIN_MIN_CHUNK_SIZE          (MIN_ALLOC_SIZE)
#define FASTBIN_COUNT                   (10)
#define FASTBIN_MAX_CHUNK_SIZE          (FASTBIN_MIN_CHUNK_SIZE + (FASTBIN_COUNT - 1) * ALLOC_SIZE_ALLIGN)
#define FASTBIN_IS_FASTBIN_SIZE(size)   (FASTBIN_MIN_CHUNK_SIZE <= (size) && (size) <= FASTBIN_MAX_CHUNK_SIZE)
#define FASTBIN_GET_BIN_OFFSET(size)    ((size - FASTBIN_MIN_CHUNK_SIZE) >> ALLOC_SIZE_ALLIGN_SHIFT)

typedef struct memory_chunk {
    size_t prev_size;
    // size of chunk, including header
    size_t size;
    // pointer to next free chunk
    // also overlaps userdata offset
    struct memory_chunk *next;
    struct memory_chunk *prev;
} memory_chunk;

typedef memory_chunk bin;

typedef struct balloc_info_struct {
    void *uninitialized_arena;
    void *end_of_arena;

    bin unsorted_bin;
    bin fastbin[FASTBIN_COUNT];
} balloc_info_struct;

balloc_info_struct balloc_info;

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

    size_t alloc_size = GET_ALLIGNED_ALLOC_SIZE(size);
    // Fastbin
    if(FASTBIN_IS_FASTBIN_SIZE(alloc_size)) {
        uint32_t offset = FASTBIN_GET_BIN_OFFSET(alloc_size);
        if(balloc_info.fastbin[offset].next != NULL) {
            memory_chunk *iter = balloc_info.fastbin[offset].next;
            balloc_info.fastbin[offset].next = iter->next;
            return GET_USERDATA_PTR(iter);
        }
    }
    // Unsorted bin
    if(balloc_info.unsorted_bin.next != NULL) {
        memory_chunk *iter = &(balloc_info.unsorted_bin);
        /**
        if(GET_USERDATA_SIZE(iter) >= size) {
            balloc_info.unsorted_bin.next = iter->next;
            if(iter->next == NULL)
                balloc_info.unsorted_bin.prev = NULL;
            else
                iter->next->prev = iter->prev;
            return GET_CHUNK_PTR(iter);
        }
        while(iter->next != NULL) {
            iter = iter->next;
            if(GET_USERDATA_SIZE(iter) >= size) {

                iter->prev->next = iter->next;
                if(iter->next == NULL)
                    balloc_info.unsorted_bin.prev = iter->prev;
                else
                    iter->next->prev = iter->prev;
            }
        }
        **/
        do {
            iter = iter->next;
            if(GET_USERDATA_SIZE(iter) >= size) {
                debug("%llx %llx\n", GET_USERDATA_SIZE(iter), size);
                if(iter->prev == NULL)
                    balloc_info.unsorted_bin.next = iter->next;
                else
                    iter->prev->next = iter->next;
                if(iter->next == NULL)
                    balloc_info.unsorted_bin.prev = iter->prev;
                else
                    iter->next->prev = iter->prev;
                return GET_USERDATA_PTR(iter);
            }
        }
        while(iter->next != NULL);
    }
    return dumb_alloc(size);
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

    memory_chunk *mchunkptr = GET_CHUNK_PTR(ptr);

    size_t size = GET_CHUNK_SIZE(mchunkptr);
    if(FASTBIN_IS_FASTBIN_SIZE(size)) {
        uint32_t offset = FASTBIN_GET_BIN_OFFSET(size);
        debug("%x %d\n", size, offset);
        mchunkptr->next = balloc_info.fastbin[offset].next;
        balloc_info.fastbin[offset].next = mchunkptr;
        return;
    }
    
    // Unsorted bin
    if(balloc_info.unsorted_bin.prev == NULL) {
        mchunkptr->next = NULL;
        mchunkptr->prev = NULL;
        balloc_info.unsorted_bin.next = mchunkptr;
        balloc_info.unsorted_bin.prev = mchunkptr;
    }
    else {
        mchunkptr->next = NULL;
        mchunkptr->prev = balloc_info.unsorted_bin.prev;
        balloc_info.unsorted_bin.prev->next = mchunkptr;
        balloc_info.unsorted_bin.prev = mchunkptr;
    }

    // Cannot reach
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
        // Maybe speed-up when free is enhanced

        /**
        if(GET_CHUNK_SIZE(mchunkptr) >= MIN_ALLOC_SIZE + GET_ALLIGNED_ALLOC_SIZE(size)) {
            size_t new_size = GET_ALLIGNED_ALLOC_SIZE(size);
            size_t left_size = GET_CHUNK_SIZE(mchunkptr) - new_size;
            ASSERT(left_size < MIN_ALLOC_SIZE, "wrong split");
            mchunkptr->size = new_size | CHECK_FLAGS(mchunkptr);
            memory_chunk *mchunkptr2free = ((void *)mchunkptr) + new_size;
            mchunkptr2free->size = left_size;
            SET_PREV_INUSE(mchunkptr2free);
            myfree(GET_USERDATA_PTR(mchunkptr2free));
            return ptr;
        }
        **/
        return ptr;
    }
    void *newptr = myalloc(size);
    if(ptr != NULL) {
        memcpy(newptr, ptr, GET_USERDATA_SIZE(mchunkptr));
    }

    return newptr;
}