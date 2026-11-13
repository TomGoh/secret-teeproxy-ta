//! Fixed Rust heap for the TEE executable. Reusing one ELF-backed mapping
//! bounds allocation-driven VMA growth during long-lived TLS relay traffic.
use std::alloc::Layout;
use std::cell::UnsafeCell;

use buddy_system_allocator::{Heap, LockedHeapWithRescue};

pub const HEAP_BYTES: usize = 96 * 1024 * 1024;
pub const ORDER: usize = 28;

#[repr(C, align(4096))]
struct Arena(UnsafeCell<[u8; HEAP_BYTES]>);

// SAFETY: The sole allocator's upstream mutex protects arena initialization,
// free-list mutation and allocation ownership. Live allocations are disjoint.
unsafe impl Sync for Arena {}

// Zero initialization places the arena in ELF NOBITS, inside the TA's existing
// 128 MiB data budget. Individual Rust allocations never request OS mappings.
static ARENA: Arena = Arena(UnsafeCell::new([0; HEAP_BYTES]));

fn initialize(heap: &mut Heap<ORDER>, _: &Layout) {
    if heap.stats_total_bytes() == 0 {
        // SAFETY: Rescue runs with the allocator's mutex held. This static is
        // page-aligned, writable for HEAP_BYTES, lives for the process lifetime,
        // and is handed to the sole allocator exactly once.
        unsafe { heap.init(ARENA.0.get().cast::<u8>() as usize, HEAP_BYTES) };
    }
}

// The module is linked into the TEE executable and into explicit host tests.
// Keeping the allocator here prevents constructing multiple heaps over ARENA.
#[cfg_attr(all(feature = "tee", not(test)), global_allocator)]
pub static ALLOCATOR: LockedHeapWithRescue<ORDER> = LockedHeapWithRescue::new(initialize);

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::GlobalAlloc;
    use std::ptr::NonNull;
    use std::sync::Mutex;

    // Host tests invoke this allocator explicitly. Their global allocator,
    // including test-harness allocations, remains the ordinary host allocator.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Allocation {
        pointer: NonNull<u8>,
        layout: Layout,
    }

    impl Allocation {
        fn new(size: usize, align: usize) -> Self {
            let layout = Layout::from_size_align(size, align).unwrap();
            // SAFETY: Layout is valid and nonzero. A successful allocation is
            // owned by this wrapper until its Drop returns the same layout.
            let pointer = NonNull::new(unsafe { ALLOCATOR.alloc(layout) })
                .expect("fixed arena exhausted unexpectedly");
            assert_eq!(pointer.as_ptr() as usize % align, 0);
            Self { pointer, layout }
        }

        fn touch(&mut self, value: u8) {
            // SAFETY: This wrapper uniquely owns the live allocation. The
            // slice covers exactly its initialized writable allocation range.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.layout.size())
            };
            bytes.fill(value);
            assert!(bytes.iter().all(|byte| *byte == value));
        }
    }

    impl Drop for Allocation {
        fn drop(&mut self) {
            // SAFETY: The pointer is live, came from ALLOCATOR, and is freed
            // exactly once using its original allocation layout.
            unsafe { ALLOCATOR.dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    fn assert_disjoint(allocations: &[Allocation]) {
        let mut ranges = allocations
            .iter()
            .map(|allocation| {
                let start = allocation.pointer.as_ptr() as usize;
                (start, start + allocation.layout.size())
            })
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        assert!(ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0));
    }

    #[test]
    fn large_request_shapes_coalesce_without_arena_growth() {
        let _guard = TEST_LOCK.lock().unwrap();
        for _ in 0..3 {
            for (count, size) in [(2, 32 * 1024 * 1024), (4, 16 * 1024 * 1024)] {
                let allocations = (0..count)
                    .map(|_| Allocation::new(size, 4096))
                    .collect::<Vec<_>>();
                assert_disjoint(&allocations);
                let small = Allocation::new(1024 * 1024, 4096);
                assert_eq!(ALLOCATOR.lock().stats_total_bytes(), HEAP_BYTES);
                drop(small);
                drop(allocations);
                assert_eq!(ALLOCATOR.lock().stats_alloc_actual(), 0);
                assert_eq!(ALLOCATOR.lock().stats_alloc_user(), 0);
            }
        }
    }

    #[test]
    fn aligned_zeroed_and_reallocated_buffers_preserve_bytes() {
        let _guard = TEST_LOCK.lock().unwrap();
        for alignment in [1, 8, 64, 4096, 65536, 1024 * 1024] {
            let mut allocation = Allocation::new(5003, alignment);
            allocation.touch(0x5a);
        }
        let layout = Layout::from_size_align(8192, 64).unwrap();
        // SAFETY: Layout is valid and nonzero. This test owns the returned
        // allocation and frees it with the current layout after reallocation.
        let pointer = unsafe { ALLOCATOR.alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        // SAFETY: Successful alloc_zeroed initialized the complete range.
        assert!(unsafe { std::slice::from_raw_parts(pointer, layout.size()) }
            .iter()
            .all(|byte| *byte == 0));
        // SAFETY: Pointer and layout identify this live allocation. The new
        // size is nonzero and representable at the original alignment.
        let larger = unsafe { ALLOCATOR.realloc(pointer, layout, 32768) };
        assert!(!larger.is_null());
        // SAFETY: Successful realloc preserves the original initialized bytes.
        assert!(unsafe { std::slice::from_raw_parts(larger, layout.size()) }
            .iter()
            .all(|byte| *byte == 0));
        let new_layout = Layout::from_size_align(32768, 64).unwrap();
        // SAFETY: Realloc transferred ownership to larger with new_layout.
        unsafe { ALLOCATOR.dealloc(larger, new_layout) };
        assert_eq!(ALLOCATOR.lock().stats_alloc_actual(), 0);
    }

    #[test]
    fn concurrent_allocations_are_disjoint_and_reclaimed() {
        let _guard = TEST_LOCK.lock().unwrap();
        std::thread::scope(|scope| {
            for worker in 0..8 {
                scope.spawn(move || {
                    for round in 0..500 {
                        let size = 1024 + ((worker * 7919 + round * 97) % 65536);
                        let mut first = Allocation::new(size, 64);
                        let mut second = Allocation::new(32768, 4096);
                        first.touch(worker as u8);
                        second.touch(round as u8);
                    }
                });
            }
        });
        assert_eq!(ALLOCATOR.lock().stats_alloc_actual(), 0);
        assert_eq!(ALLOCATOR.lock().stats_total_bytes(), HEAP_BYTES);
    }

    #[test]
    fn invalid_layouts_and_exhaustion_cannot_expand_the_arena() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert!(Layout::from_size_align(64, 3).is_err());
        assert!(Layout::from_size_align(usize::MAX, 8).is_err());
        let allocation = Allocation::new(4096, 4096);
        for layout in [
            Layout::from_size_align(HEAP_BYTES + 1, 8).unwrap(),
            Layout::from_size_align(4096, 128 * 1024 * 1024).unwrap(),
            Layout::from_size_align(isize::MAX as usize, 1).unwrap(),
        ] {
            // SAFETY: Each layout is valid and nonzero. Requests exceed the
            // arena's largest possible block and must return a null pointer.
            assert!(unsafe { ALLOCATOR.alloc(layout) }.is_null());
            assert_eq!(ALLOCATOR.lock().stats_total_bytes(), HEAP_BYTES);
        }
        drop(allocation);
        assert_eq!(ALLOCATOR.lock().stats_alloc_actual(), 0);
    }
}
