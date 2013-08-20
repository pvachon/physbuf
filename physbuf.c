#include <tsl/list.h>
#include <tsl/assert.h>
#include <tsl/diag.h>
#include <tsl/errors.h>
#include <tsl/panic.h>
#include <tsl/bits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <unistd.h>

typedef size_t paddr_t;

struct phys_buf {
    void *addr;
    paddr_t phys_addr;
    struct list_entry pnode;
};

struct buf_mgr {
    struct list_entry free_phys_buf;
    void *all_mem;
    size_t all_mem_length;
    struct phys_buf *phys_buf_desc;
    size_t num_phys_buf;
    size_t used_phys_buf;
};

#define SAFE_CALLOC(tgt, count, cleanup, retval) \
    ({      __typeof__(tgt) __temp_calloc_val = NULL;                                       \
            __temp_calloc_val = (__typeof__(tgt))calloc( (sizeof(*(tgt))), (count) );       \
            if ( (__temp_calloc_val) == NULL ) {                                            \
                DIAG("Failed to allocate %zu bytes for " #tgt, sizeof(*tgt));               \
                (tgt) = NULL;                                                               \
                (retval) = A_E_NOMEM;                                                       \
                goto cleanup;                                                               \
            }                                                                               \
            __temp_calloc_val;                                                              \
     })

static
aresult_t buf_mgr_prepare_buf_info(struct buf_mgr *mgr,
                                   struct phys_buf *buf, void *virt_addr, size_t page_shift, FILE *mem_info)
{
    aresult_t ret = A_OK;

    memset(buf, 0, sizeof(*buf));

    size_t page_mask = ~((1 << page_shift) - 1);

    size_t vaddr = (size_t)virt_addr;

    if (fseek(mem_info, (vaddr >> page_shift) * 8, SEEK_SET) < 0) {
        DIAG("Failed to seek to page information for virtual address 0x%p.", virt_addr);
        ret = A_E_INVAL;
        goto done;
    } 

    uint64_t pte = 0;
    if (fread(&pte, 1, sizeof(pte), mem_info) < sizeof(pte)) {
        DIAG("Failed to read Page Table Entry for virtual address 0x%p.", virt_addr);
        ret = A_E_INVAL;
        goto done;
    }

    if (pte & (1ull << 63) == 0) {
        DIAG("Page for virtual address 0x%p is not present in memory.", virt_addr);
        ret = A_E_INVAL;
        goto done;
    }

    paddr_t phys_addr = ((pte & TSL_MASK(54)) << page_shift) + (vaddr & TSL_MASK(page_shift));

    buf->addr = virt_addr;
    buf->phys_addr = phys_addr;

    list_append(&mgr->free_phys_buf, &buf->pnode);

done:
    return ret;
}

/**
 * Typically, obj_size rounded to obj_align_p2 should evenly divide the size of a page - otherwise,
 * you're going to have a bad time..
 */
aresult_t buf_mgr_init(struct buf_mgr **new_mgr, size_t nr_obj, size_t obj_size, size_t obj_align_p2, int huge_pages)
{
    aresult_t ret = A_OK;
    struct buf_mgr *mgr = NULL;
    FILE *mi = NULL;

    TSL_ASSERT_ARG(new_mgr != NULL);
    TSL_ASSERT_ARG(obj_size != 0);
    TSL_ASSERT_ARG(nr_obj != 0);

    size_t page_size = 0;
    size_t page_shift = 12;
    if (huge_pages) {
        /* FIXME: this shouldn't be hard coded */
        page_size = 2 * 1024 * 1024;
        page_shift = 21;
    } else {
        page_size = sysconf(_SC_PAGE_SIZE);
        /* FIXME: page_shift shouldn't be hard coded */
    }

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (huge_pages) {
        flags |= MAP_HUGETLB;
        DIAG("Using Huge Pages");
    }

    *new_mgr = NULL;

    mgr = SAFE_CALLOC(mgr, 1, done, ret);

    size_t obj_total_size = BL_ROUND_POW2(obj_size, obj_align_p2);
    DIAG("Rounding object to %zu (object size = %zu, rounded = %zu)", obj_align_p2, obj_size, obj_total_size);
    size_t mmap_size = nr_obj * obj_total_size;

    if ( (mgr->all_mem = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, flags, -1, 0)) == MAP_FAILED ) {
        PDIAG("Failed to allocate %zu bytes using mmap (%zu objects of size %zu)", mmap_size, nr_obj, obj_total_size);
        mgr->all_mem = NULL;
        ret = A_E_NOMEM;
        goto done;
    }

    mgr->all_mem_length = mmap_size;

    /* Lock the new memory region - physical addresses could become meaningless otherwise */
    if (mlock(mgr->all_mem, mgr->all_mem_length) < 0) {
        PDIAG("Failed to lock pages to be used.");
        ret = A_E_NOMEM;
        goto done;
    }

    /* Open /proc/self/mem so we can map virtual page addresses to physical addresses */
    mi = fopen("/proc/self/pagemap", "rb");

    if (mi == NULL) {
        PDIAG("Failed to open /proc/self/mem for reading.");
        goto done;
    }

    /* Allocate enough physical buffer descriptors */
    mgr->phys_buf_desc = SAFE_CALLOC(mgr->phys_buf_desc, nr_obj, done, ret);

    list_init(&mgr->free_phys_buf);

    /* Initialize each physical buffer descriptor */
    for (size_t i = 0; i < nr_obj; i++) {
        if (AFAILED(ret = buf_mgr_prepare_buf_info(mgr, &mgr->phys_buf_desc[i],
                                                   mgr->all_mem + (i * obj_total_size), page_shift, mi)))
        {
            DIAG("Failed to prepare a physical buffer (id = %zu). Aborting.", i);
            goto done;
        }
    }

done:
    if (mi != NULL) {
        fclose(mi);
        mi = NULL;
    }

    if (AFAILED(ret)) {
        DIAG("Cleaning up after a failure in initializing the buffer manager.");
        if (mgr) {
            if (mgr->all_mem) {
                munmap(mgr->all_mem, mgr->all_mem_length);
                mgr->all_mem = NULL;
            }

            if (mgr->phys_buf_desc != NULL) {
                free(mgr->phys_buf_desc);
                mgr->phys_buf_desc = NULL;
            }

            free(mgr);
            mgr = NULL;
        }
    }

    return ret;
}

int main(int argc, char *argv[])
{
    struct buf_mgr *mgr = NULL;

    if (AFAILED(buf_mgr_init(&mgr, 128, 2048, 11, 0))) {
        fprintf(stderr, "Failed to initialize physical buffer manager. Aborting.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

