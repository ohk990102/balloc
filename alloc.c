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
#define SBRK_SIZE_ALLIGN            (14)
#define ALLOC_SIZE_ALLIGN_SHIFT     (4)
#define ALLOC_SIZE_ALLIGN           (1 << ALLOC_SIZE_ALLIGN_SHIFT)

#define MIN_ALLOC_SIZE              (sizeof(memory_chunk))
#define HEADER_SIZE                 (offsetof(memory_chunk, next))
#define USED_BY_PREV_CHUNK_SIZE     (offsetof(memory_chunk, size))
#define UNINITIALIZED_ARENA_SIZE    (balloc_info.end_of_arena - balloc_info.uninitialized_arena)

// Define macro functions
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define CHECK_FLAGS(chunk)          (((chunk)->size) & (ALLOC_SIZE_ALLIGN - 1))

#define CHECK_ADJ_PREV_INUSE(chunk)     ((chunk)->size & 0x1)
#define SET_ADJ_PREV_INUSE(chunk, bit)       (((bit) == 0) ? ((chunk)->size &= ~(0x1)) : ((chunk)->size |= 0x1))

#define GET_USERDATA_SIZE(chunk)    ((((chunk)->size) & (~(ALLOC_SIZE_ALLIGN - 1))) - (HEADER_SIZE - USED_BY_PREV_CHUNK_SIZE))
#define GET_CHUNK_SIZE(chunk)       (((chunk)->size) & (~(ALLOC_SIZE_ALLIGN - 1)))
#define GET_USERDATA_PTR(chunk)     (((void *)(chunk))+offsetof(memory_chunk, next))
#define GET_CHUNK_PTR(ptr)          ((memory_chunk *)(((void *)(ptr))-offsetof(memory_chunk, next)))
#define GET_ADJ_NEXT_CHUNK_PTR(chunk)   ((memory_chunk *)(((void *)(chunk))+GET_CHUNK_SIZE(chunk)))
#define GET_ADJ_PREV_CHUNK_PTR(chunk)   ((memory_chunk *)(((void *)(chunk))-chunk->prev_size))

#define GET_ALLIGNED_SIZE_MULTIPLES(size, multiples)        ((((size) + (multiples) - 1) / (multiples)) * (multiples))
#define GET_ALLIGNED_SIZE_SHIFT(size, shift)                ((((size) + (1 << (shift)) - 1) >> (shift)) << (shift))
#define GET_ALLIGNED_ALLOC_SIZE(size)                       (MAX((GET_ALLIGNED_SIZE_SHIFT((size) + HEADER_SIZE - USED_BY_PREV_CHUNK_SIZE, \
                                                                ALLOC_SIZE_ALLIGN_SHIFT)), GET_ALLIGNED_SIZE_SHIFT(MIN_ALLOC_SIZE, \
                                                                ALLOC_SIZE_ALLIGN_SHIFT)))

#define IS_CHUNK(chunk)                 ((void *)(chunk) < balloc_info.uninitialized_arena)

// Fastbin macros
#define FASTBIN_MIN_CHUNK_SIZE          (MIN_ALLOC_SIZE)
#define FASTBIN_COUNT                   (30)
#define FASTBIN_MAX_CHUNK_SIZE          (FASTBIN_MIN_CHUNK_SIZE + FASTBIN_COUNT * ALLOC_SIZE_ALLIGN)
#define FASTBIN_IS_FASTBIN_SIZE(size)   (FASTBIN_MIN_CHUNK_SIZE <= (size) && (size) < FASTBIN_MAX_CHUNK_SIZE)
#define FASTBIN_GET_BIN_OFFSET(size)    ((size - FASTBIN_MIN_CHUNK_SIZE) >> ALLOC_SIZE_ALLIGN_SHIFT)

// Smallbin macros
#define SMALLBIN_MIN_CHUNK_SIZE         (MIN_ALLOC_SIZE)
#define SMALLBIN_COUNT                  (126)
#define SMALLBIN_MAX_CHUNK_SIZE         (SMALLBIN_MIN_CHUNK_SIZE + SMALLBIN_COUNT * ALLOC_SIZE_ALLIGN)
#define SMALLBIN_IS_SMALLBIN_SIZE(size) (SMALLBIN_MIN_CHUNK_SIZE <= (size) && (size) < SMALLBIN_MAX_CHUNK_SIZE)
#define SMALLBIN_GET_BIN_OFFSET(size)   ((size - SMALLBIN_MIN_CHUNK_SIZE) >> ALLOC_SIZE_ALLIGN_SHIFT)


typedef struct memory_chunk {
    // size of previous chunk
    // note that this member overlaps userdata of previous chunk
    size_t prev_size;
    // size of chunk, including flags
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
    bin smallbin[SMALLBIN_COUNT];
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

void initialize_balloc() {
    balloc_info.unsorted_bin.prev = &(balloc_info.unsorted_bin);
    balloc_info.unsorted_bin.next = &(balloc_info.unsorted_bin);
    for(int i = 0; i < SMALLBIN_COUNT; i++) {
        balloc_info.smallbin[i].prev = &(balloc_info.smallbin[i]);
        balloc_info.smallbin[i].next = &(balloc_info.smallbin[i]);
    }
    debug("%x\n", FASTBIN_MAX_CHUNK_SIZE);
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
    ASSERT(alloc_size < MIN_ALLOC_SIZE, "smaller alloc_size");
    if(UNINITIALIZED_ARENA_SIZE < alloc_size + USED_BY_PREV_CHUNK_SIZE)
        if(!increase_arena(alloc_size + USED_BY_PREV_CHUNK_SIZE))
            return NULL;   
    
    memory_chunk *mchunkptr = balloc_info.uninitialized_arena;
    mchunkptr->size = alloc_size;
    SET_ADJ_PREV_INUSE(mchunkptr, 1);
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
    if(balloc_info.uninitialized_arena == NULL) {
        initialize_balloc();
        if(!increase_arena(GET_ALLIGNED_ALLOC_SIZE(size)))
            return NULL;
    }

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
    // Small bin
    if(SMALLBIN_IS_SMALLBIN_SIZE(alloc_size)) {
        uint32_t offset = SMALLBIN_GET_BIN_OFFSET(alloc_size);
        if(balloc_info.smallbin[offset].next != &(balloc_info.smallbin[offset])) {
            memory_chunk *mchunkptr = balloc_info.smallbin[offset].next;
            mchunkptr->prev->next = mchunkptr->next;
            mchunkptr->next->prev = mchunkptr->prev;
            memory_chunk *nextchunkptr = GET_ADJ_NEXT_CHUNK_PTR(mchunkptr);
            if(IS_CHUNK(nextchunkptr))
                SET_ADJ_PREV_INUSE(nextchunkptr, 1);    // TODO: check if the condition is not needed
            return GET_USERDATA_PTR(mchunkptr);
        }
    }



    // Unsorted bin
    memory_chunk *iter = &(balloc_info.unsorted_bin);
    while(iter->next != &(balloc_info.unsorted_bin)) {
        iter = iter->next;
        if(GET_USERDATA_SIZE(iter) >= size) {
            debug("%llx %llx\n", GET_USERDATA_SIZE(iter), size);
            iter->prev->next = iter->next;
            iter->next->prev = iter->prev;
            SET_ADJ_PREV_INUSE(GET_ADJ_NEXT_CHUNK_PTR(iter), 1);
            return GET_USERDATA_PTR(iter);
        }
    }
    return dumb_alloc(size);
}

void put_unsortedbin(memory_chunk *mchunkptr) {
    memory_chunk *endchunkptr = GET_ADJ_NEXT_CHUNK_PTR(mchunkptr);
    while(!CHECK_ADJ_PREV_INUSE(mchunkptr)) {
        mchunkptr = GET_ADJ_PREV_CHUNK_PTR(mchunkptr);
        mchunkptr->prev->next = mchunkptr->next;
        mchunkptr->next->prev = mchunkptr->prev;
    }
    if(!IS_CHUNK(endchunkptr)) {
        // Ensure that free chunk and uninitialized_arena is not joint
        balloc_info.uninitialized_arena = mchunkptr;
        return;
    }
    while(IS_CHUNK(GET_ADJ_NEXT_CHUNK_PTR(endchunkptr)) && !CHECK_ADJ_PREV_INUSE(GET_ADJ_NEXT_CHUNK_PTR(endchunkptr))) {
        endchunkptr->prev->next = endchunkptr->next;
        endchunkptr->next->prev = endchunkptr->prev;
        endchunkptr = GET_ADJ_NEXT_CHUNK_PTR(endchunkptr);
    }
    size_t new_size = (void *)endchunkptr - (void *)mchunkptr;
    
    uint8_t save_bit = CHECK_ADJ_PREV_INUSE(mchunkptr);
    mchunkptr->size = new_size;
    SET_ADJ_PREV_INUSE(mchunkptr, save_bit);
    endchunkptr->prev_size = new_size;
    SET_ADJ_PREV_INUSE(endchunkptr, 0);

    mchunkptr->next = &(balloc_info.unsorted_bin);
    mchunkptr->prev = balloc_info.unsorted_bin.prev;
    balloc_info.unsorted_bin.prev->next = mchunkptr;
    balloc_info.unsorted_bin.prev = mchunkptr;
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

    put_unsortedbin(mchunkptr);
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
            SET_ADJ_PREV_INUSE(mchunkptr2free);
            myfree(GET_USERDATA_PTR(mchunkptr2free));
            return ptr;
        }
        **/
        return ptr;
    }
    void *newptr = myalloc(size);
    memcpy(newptr, ptr, GET_USERDATA_SIZE(mchunkptr));
    myfree(ptr);

    
    return newptr;
}