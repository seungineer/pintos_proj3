/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include <stdbool.h>

#include "hash.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"
#include "vm/uninit.h"
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
#define VA_MASK(va) ((uint64_t)(va) & ~(uint64_t)0xFFF)
#define USER_STACK_MIN (USER_STACK - (1 << 20))
struct list frame_table;
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
    list_init(&frame_table);
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* 이니셜라이저로 보류 중인 페이지 객체를 만듭니다.
페이지를 만들려면 직접 만들지 말고
이 함수 또는 `vm_alloc_page`를 통해 만드세요.*/
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux)
// ↳ page type, page의 가상주소?, write 가능여부, page를 실제로 올릴때 실행하는 함수(vm_initializer), vm_initializer함수의 실행시에 넘겨주는 인자
{
    ASSERT(VM_TYPE(type) != VM_UNINIT)  // vm_type은 VM_ANON과 VM_FILE만 가능하다.

    struct supplemental_page_table *spt = &thread_current()->spt;

    if (spt_find_page(spt, upage) == NULL) {  // spt에 upage에 해당하는 페이지가 없다면
        struct page *p = (struct page *)malloc(sizeof(struct page));

        bool (*initializer)(struct page *, enum vm_type, void *);

        // ↳페이지 타입에 따라 initializer가 될 초기화 함수를 매칭
        if (VM_TYPE(type) == VM_ANON)
            initializer = anon_initializer;
        else if (VM_TYPE(type) == VM_FILE)
            initializer = file_backed_initializer;

        uninit_new(p, upage, init, type, aux, initializer);  // UNINIT 페이지 생성
        p->writable = writable;

        return spt_insert_page(spt, p);  // spt에 unint 페이지 추가
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// spt에서 va에 해당하는 page를 찾아서 반환

static int cnt = 0;
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    struct page *page = NULL;
    page = malloc(sizeof(struct page));
    struct hash_elem *hash_element;
    page->va = pg_round_down(va);  // 페이지를 찾을때는 rounddown  -> up은 할당크기 맞출때
    hash_element = hash_find(spt, &page->hash_elem);
    free(page);  // 할당된 메모리 해제
    if (hash_element) {
        return hash_entry(hash_element, struct page, hash_elem);  // hash_entry로 hash_elem을 page로 변환
    }
    return NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED) {
    int succ = false;
    // REVIEW INSERT_PAGE
    if (hash_insert(&spt->hash_page, &page->hash_elem) == NULL) {  // 잘 추가되었으면 NULL반환
        succ = true;
    }
    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void) {
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */
    // victim = list_pop_front(&frame_table);
    // REVIEW list가 비어있다면 ?
    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    swap_out(victim->page);
    /* TODO: swap out the victim and return the evicted frame. */
    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/

static struct frame *
vm_get_frame(void) {
    struct frame *frame = NULL;
    frame = malloc(sizeof(struct frame));
    void *kva = palloc_get_page(PAL_USER);
    if (kva == NULL) {
        PANIC("TODO: swap out");
    }
    frame->kva = kva;
    frame->page = NULL;
    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    // list_push_back(&frame_table, &frame->frame_elem);
    return frame;
}
/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED) {
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED) {
}
/* Return true on success */

bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct thread *cur = thread_current();
    struct supplemental_page_table *spt UNUSED = &cur->spt;
    struct page *page = NULL;
    if (addr == NULL) {
        return false;
    }
    if (is_kernel_vaddr(addr)) {
        return false;
    }
    if ((addr > USER_STACK_MIN) && ((addr >= f->rsp) || (addr == (f->rsp - 8)))) {
        vm_stack_growth(addr);
    }
    page = spt_find_page(spt, addr);
    if (page == NULL) {
        return false;
    }
    return vm_do_claim_page(page);  // page 할당
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {  // va에 해당하는 페이지를 할당
    struct page *page = NULL;
    struct supplemental_page_table spt = thread_current()->spt;
    page = spt_find_page(&spt, va);
    if (page == NULL) {
        return false;
    }
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
// REVIEW
static bool
vm_do_claim_page(struct page *page) {  // va 페이지를만들고 프레임에 할당한 페이지
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    struct thread *current = thread_current();
    bool writable = is_writable(current->pml4);
    pml4_set_page(current->pml4, page->va, frame->kva, page->writable);  // pml4에 page를 할당

    return swap_in(page, frame->kva);
}

unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    uint64_t masked_va = VA_MASK(p->va);  // VA_MASK
    return hash_bytes(&masked_va, sizeof masked_va);
}

bool page_less(const struct hash_elem *a_,
               const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    hash_init(spt, page_hash, page_less, NULL);
}

bool supplemental_page_table_copy(struct supplemental_page_table *dst, struct supplemental_page_table *src) {
    struct hash_iterator i;
    struct page *page;  // src의 페이지에 쓰기위한 변수
    enum vm_type type;
    void *upage;  // upage -> 가상주소
    bool writable;

    hash_first(&i, &src->hash_page);  // src의 hash_page의 첫번째 페이지를 i에 넣어주는 함수
    while (hash_next(&i)) {
        page = hash_entry(hash_cur(&i), struct page, hash_elem);
        type = page->operations->type;
        upage = page->va;
        writable = page->writable;

        if (type == VM_UNINIT) {
            vm_initializer *init = page->uninit.init;
            void *aux = page->uninit.aux;
            if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux))
                return false;
            continue;
        }

        if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, NULL))  // upage에 해당하는 페이지를 할당
            return false;                                                        // 할당 못하면 false 반환

        if (!vm_claim_page(upage))  // upage에 해당하는 페이지를 할당
            return false;           // 할당 못하면 false 반환

        struct page *dst_page = spt_find_page(dst, upage);       // 이제 할당된 페이지를 dst_page에 넣기
        memcpy(dst_page->frame->kva, page->frame->kva, PGSIZE);  // 할당된 페이지의 kva에 src의 kva를 복사 - 페이지 크기만큼
    }
    return true;
}

void destroy_hash(const struct hash_elem *p_) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    vm_dealloc_page(p);
    // vm_dealloc_page(p)가 결국 destroy(p)랑 free(p)를 호출함
    // destroy(p);
    // free(p);
}

// type, upage, writable
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    hash_clear(&spt->hash_page, destroy_hash);  // hash table 버킷을 모두 비우고, 삭제해줌
}
