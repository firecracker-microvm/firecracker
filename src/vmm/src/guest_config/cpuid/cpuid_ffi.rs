// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::alloc::Layout;
use std::cmp::{Eq, PartialEq};
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::mem::{size_of, transmute, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use super::{CpuidEntry, CpuidKey};

/// Converts `u32` to `usize`.
#[cfg(target_pointer_width = "64")]
fn from_u32(x: u32) -> usize {
    // The wrapping `cfg` guarantees this is safe.
    #[allow(clippy::unwrap_used)]
    usize::try_from(x).unwrap()
}

/// Mimic of the currently unstable
/// [`Vec::into_raw_parts`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.into_raw_parts)
/// .
fn vec_into_raw_parts<T>(v: Vec<T>) -> (*mut T, usize, usize) {
    let mut me = std::mem::ManuallyDrop::new(v);
    (me.as_mut_ptr(), me.len(), me.capacity())
}

/// A rusty mimic of
/// [`kvm_cpuid`](https://elixir.bootlin.com/linux/v5.10.129/source/arch/x86/include/uapi/asm/kvm.h#L226)
/// .
///
/// [`RawCpuid`] has an identical memory layout to
/// [`kvm_cpuid`](https://elixir.bootlin.com/linux/v5.10.129/source/arch/x86/include/uapi/asm/kvm.h#L226)
/// .
///
/// This allows [`RawCpuid`] to function as a simpler replacement for [`kvm_bindings::CpuId`]. In
/// the future it may replace [`kvm_bindings::CpuId`] fully.
///
/// For implementation details see <https://doc.rust-lang.org/nomicon/vec/vec.html>.
#[derive(Debug)]
#[repr(C)]
pub struct RawCpuid {
    /// Number of entries.
    nent: u32,
    /// Padding.
    padding: Padding<{ size_of::<u32>() }>,
    /// Pointer to entries.
    entries: NonNull<RawKvmCpuidEntry>,
    /// Marker type.
    _marker: PhantomData<RawKvmCpuidEntry>,
}

/// Error type for [`RawCpuid::resize`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Failed to resize: {0}")]
pub struct RawCpuidResizeError(std::alloc::LayoutError);

impl super::CpuidTrait for RawCpuid {
    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn get(&self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&CpuidEntry> {
        let entry_opt = self
            .iter()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);

        entry_opt.map(|entry| {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: The `RawKvmCpuidEntry` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &[u8; size_of::<RawKvmCpuidEntry>()] = transmute(entry);
                let arr2: &[u8; size_of::<CpuidEntry>()] = arr[8..28].try_into().unwrap();
                transmute::<_, &CpuidEntry>(arr2)
            }
        })
    }

    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn get_mut(&mut self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&mut CpuidEntry> {
        let entry_opt = self
            .iter_mut()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);
        entry_opt.map(|entry| {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: The `RawKvmCpuidEntry` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &mut [u8; size_of::<RawKvmCpuidEntry>()] = transmute(entry);
                let arr2: &mut [u8; size_of::<CpuidEntry>()] =
                    (&mut arr[8..28]).try_into().unwrap();
                transmute::<_, &mut CpuidEntry>(arr2)
            }
        })
    }
}

/// Error type for [`RawCpuid::push`].
#[derive(Debug, thiserror::Error)]
pub enum RawCpuidPushError {
    /// Failed to push an element as this results in an overflow.
    #[error("Failed to push an element as this results in an overflow.")]
    Overflow,
    /// Failed to push element as this results in an invalid layout.
    #[error("Failed to push element as this results in an invalid layout.")]
    Layout(std::alloc::LayoutError),
}

impl RawCpuid {
    /// Alias for [`RawCpuid::default()`].
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Returns number of elements.
    #[inline]
    #[must_use]
    pub fn nent(&self) -> u32 {
        self.nent
    }
    /// Returns a reference to an entry for a given leaf (function) and sub-leaf (index).
    ///
    /// Returning `None` if it is not present.
    #[inline]
    #[must_use]
    pub fn get(&self, leaf: u32, sub_leaf: u32) -> Option<&RawKvmCpuidEntry> {
        self.iter()
            .find(|entry| entry.function == leaf && entry.index == sub_leaf)
    }
    /// Returns a mutable reference entry for a given leaf (function) and sub-leaf (index).
    ///
    /// Returning `None` if it is not present.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, leaf: u32, sub_leaf: u32) -> Option<&mut RawKvmCpuidEntry> {
        self.iter_mut()
            .find(|entry| entry.function == leaf && entry.index == sub_leaf)
    }

    /// Pushes a new element.
    ///
    /// # Errors
    ///
    /// When:
    /// - `self.nent.checked(1)` errors.
    /// - `Layout::array::<RawKvmCpuidEntry>()` errors.
    #[allow(clippy::cast_ptr_alignment)]
    #[inline]
    pub fn push(&mut self, entry: RawKvmCpuidEntry) -> Result<(), RawCpuidPushError> {
        let new = self
            .nent
            .checked_add(1)
            .ok_or(RawCpuidPushError::Overflow)?;

        let new_layout =
            Layout::array::<RawKvmCpuidEntry>(from_u32(new)).map_err(RawCpuidPushError::Layout)?;

        let nent_usize = from_u32(self.nent);

        let new_ptr = if self.nent == 0 {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: Always safe.
            unsafe { std::alloc::alloc(new_layout) }
        } else {
            let old_layout =
                Layout::array::<RawKvmCpuidEntry>(nent_usize).map_err(RawCpuidPushError::Layout)?;
            let old_ptr = self.entries.as_ptr().cast::<u8>();

            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: Always safe.
            unsafe { std::alloc::realloc(old_ptr, old_layout, new_layout.size()) }
        };

        self.entries = match NonNull::new(new_ptr.cast::<RawKvmCpuidEntry>()) {
            Some(ptr) => ptr,
            None => std::alloc::handle_alloc_error(new_layout),
        };

        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: `self.entries.as_ptr().add(net)` is within the allocated range.
        unsafe {
            std::ptr::write(self.entries.as_ptr().add(nent_usize), entry);
        }

        self.nent = new;

        Ok(())
    }
    /// Pops entry from end.
    ///
    /// # Panics
    ///
    /// On allocation failure.
    #[inline]
    pub fn pop(&mut self) -> Option<RawKvmCpuidEntry> {
        if let Some(new) = self.nent.checked_sub(1) {
            self.nent = new;
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: We know the pointer is valid.
            unsafe {
                Some(std::ptr::read(
                    self.entries.as_ptr().add(from_u32(self.nent)),
                ))
            }
        } else {
            None
        }
    }
}

#[allow(clippy::cast_ptr_alignment, clippy::unwrap_used)]
impl Clone for RawCpuid {
    #[inline]
    fn clone(&self) -> Self {
        if self.nent == 0 {
            Self::new()
        } else {
            let nent_usize = from_u32(self.nent);
            let layout = Layout::array::<RawKvmCpuidEntry>(nent_usize).unwrap();

            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: Always safe.
            let ptr = unsafe { std::alloc::alloc(layout) };

            let entries = match NonNull::new(ptr.cast::<RawKvmCpuidEntry>()) {
                Some(p) => p,
                None => std::alloc::handle_alloc_error(layout),
            };

            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: `entries` is newly allocated so will not overlap `self.entries`, and both are
            // non-null.
            unsafe {
                std::ptr::copy_nonoverlapping(self.entries.as_ptr(), entries.as_ptr(), nent_usize);
            }
            Self {
                nent: self.nent,
                padding: Padding::default(),
                entries,
                _marker: PhantomData,
            }
        }
    }
}

impl PartialEq for RawCpuid {
    #[allow(clippy::indexing_slicing)]
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        if self.nent == other.nent {
            for i in 0..from_u32(self.nent) {
                if self[i] != other[i] {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }
}

impl Eq for RawCpuid {}

// JUSTIFICATION: There is no safe alternative.
// SAFETY: Always safe.
unsafe impl Send for RawCpuid {}

// JUSTIFICATION: There is no safe alternative.
// SAFETY: Always safe.
unsafe impl Sync for RawCpuid {}

impl Default for RawCpuid {
    #[inline]
    fn default() -> Self {
        Self {
            nent: 0,
            padding: Padding::default(),
            entries: NonNull::dangling(),
            _marker: PhantomData,
        }
    }
}

// We implement custom drop which drops all entries using `self.nent`
impl Drop for RawCpuid {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn drop(&mut self) {
        if self.nent != 0 {
            let cap = self.nent;

            // Drop elements
            while self.pop().is_some() {}

            // Deallocate memory
            let layout = Layout::array::<RawKvmCpuidEntry>(from_u32(cap)).unwrap();

            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: Always safe.
            unsafe {
                std::alloc::dealloc(self.entries.as_ptr().cast::<u8>(), layout);
            }
        }
    }
}

impl Deref for RawCpuid {
    type Target = [RawKvmCpuidEntry];

    #[allow(clippy::unwrap_used)]
    #[inline]
    fn deref(&self) -> &Self::Target {
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: Always safe.
        unsafe { std::slice::from_raw_parts(self.entries.as_ptr(), from_u32(self.nent)) }
    }
}

impl DerefMut for RawCpuid {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: Always safe.
        unsafe { std::slice::from_raw_parts_mut(self.entries.as_ptr(), from_u32(self.nent)) }
    }
}

impl From<kvm_bindings::CpuId> for RawCpuid {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn from(value: kvm_bindings::CpuId) -> Self {
        // As cannot acquire ownership of the underlying slice, we clone it.
        let cloned = value.as_slice().to_vec();
        let (ptr, len, _cap) = vec_into_raw_parts(cloned);
        Self {
            nent: u32::try_from(len).unwrap(),
            padding: Padding::default(),
            entries: NonNull::new(ptr.cast::<RawKvmCpuidEntry>()).unwrap(),
            _marker: PhantomData,
        }
    }
}

impl From<Vec<RawKvmCpuidEntry>> for RawCpuid {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn from(vec: Vec<RawKvmCpuidEntry>) -> Self {
        let (ptr, len, _cap) = vec_into_raw_parts(vec);
        Self {
            nent: u32::try_from(len).unwrap(),
            padding: Padding::default(),
            entries: NonNull::new(ptr.cast::<RawKvmCpuidEntry>()).unwrap(),
            _marker: PhantomData,
        }
    }
}

impl FromIterator<RawKvmCpuidEntry> for RawCpuid {
    #[inline]
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = RawKvmCpuidEntry>,
    {
        let vec = iter.into_iter().collect::<Vec<RawKvmCpuidEntry>>();
        Self::from(vec)
    }
}

impl From<RawCpuid> for kvm_bindings::CpuId {
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn from(this: RawCpuid) -> Self {
        let cpuid_slice =
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: Always safe.
            unsafe { std::slice::from_raw_parts(this.entries.as_ptr(), from_u32(this.nent)) };

        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: Always safe.
        let kvm_bindings_slice = unsafe { transmute(cpuid_slice) };

        kvm_bindings::CpuId::from_entries(kvm_bindings_slice).unwrap()
    }
}

/// A structure for owning unused memory for padding.
///
/// A wrapper around an uninitialized `N` element array of `u8`s (`MaybeUninit<[u8;N]>` constructed
/// with `Self(MaybeUninit::uninit())`).
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Padding<const N: usize>(MaybeUninit<[u8; N]>);

impl<const N: usize> Default for Padding<N> {
    #[inline]
    fn default() -> Self {
        Self(MaybeUninit::uninit())
    }
}

impl<const N: usize> PartialEq for Padding<N> {
    #[inline]
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<const N: usize> Eq for Padding<N> {}

/// Definitions from `kvm/arch/x86/include/uapi/asm/kvm.h
#[derive(
    Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy,
)]
pub struct KvmCpuidFlags(pub u32);
impl KvmCpuidFlags {
    /// Zero.
    pub const EMPTY: Self = Self(0);
    /// Indicates if the `index` field is used for indexing sub-leaves (if false, this CPUID leaf
    /// has no subleaves).
    pub const SIGNIFICANT_INDEX: Self = Self(1 << 0);
    /// Deprecated.
    pub const STATEFUL_FUNC: Self = Self(1 << 1);
    /// Deprecated.
    pub const STATE_READ_NEXT: Self = Self(1 << 2);
}

#[allow(clippy::derivable_impls)]
impl Default for KvmCpuidFlags {
    #[inline]
    fn default() -> Self {
        Self(0)
    }
}

/// CPUID entry (a mimic of <https://elixir.bootlin.com/linux/v5.10.129/source/arch/x86/include/uapi/asm/kvm.h#L232>).
#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct RawKvmCpuidEntry {
    /// CPUID function (leaf).
    pub function: u32,
    /// CPUID index (subleaf).
    pub index: u32,
    /// KVM CPUID flags.
    pub flags: KvmCpuidFlags,
    /// EAX register.
    pub eax: u32,
    /// EBX register.
    pub ebx: u32,
    /// ECX register.
    pub ecx: u32,
    /// EDX register.
    pub edx: u32,
    /// CPUID entry padding.
    pub padding: Padding<{ size_of::<[u32; 3]>() }>,
}
impl fmt::LowerHex for RawKvmCpuidEntry {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawKvmCpuidEntry")
            .field("function", &format!("{:x}", self.function))
            .field("index", &format!("{:x}", self.index))
            .field("flags", &format!("{:x}", self.flags.0))
            .field("eax", &format!("{:x}", self.eax))
            .field("ebx", &format!("{:x}", self.ebx))
            .field("ecx", &format!("{:x}", self.ecx))
            .field("edx", &format!("{:x}", self.edx))
            .finish()
    }
}

#[allow(clippy::unwrap_used, clippy::print_stdout, clippy::use_debug)]
#[cfg(test)]
mod tests {
    use kvm_bindings::KVM_MAX_CPUID_ENTRIES;

    use super::super::{CpuidRegisters, CpuidTrait};
    use super::*;

    #[test]
    fn raw_cpuid_nent() {
        let raw_cpuid = RawCpuid::new();
        assert_eq!(raw_cpuid.nent(), 0);
    }

    #[test]
    fn raw_cpuid_cpuid_trait_get_mut() {
        let mut raw_cpuid = RawCpuid::new();
        raw_cpuid
            .push(RawKvmCpuidEntry {
                function: 0,
                index: 0,
                flags: KvmCpuidFlags::EMPTY,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: Padding::default(),
            })
            .unwrap();

        let mut_leaf = <RawCpuid as CpuidTrait>::get_mut(
            &mut raw_cpuid,
            &CpuidKey {
                leaf: 0,
                subleaf: 0,
            },
        )
        .unwrap();

        assert_eq!(
            mut_leaf,
            &mut CpuidEntry {
                flags: KvmCpuidFlags::EMPTY,
                result: CpuidRegisters {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                }
            }
        );
        let set_result = CpuidRegisters {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        };
        mut_leaf.result = set_result.clone();

        let leaf = <RawCpuid as CpuidTrait>::get(
            &raw_cpuid,
            &CpuidKey {
                leaf: 0,
                subleaf: 0,
            },
        )
        .unwrap();
        assert_eq!(
            leaf,
            &CpuidEntry {
                flags: KvmCpuidFlags::EMPTY,
                result: set_result
            }
        );
    }

    #[test]
    fn raw_cpuid_get_mut() {
        let mut entry = RawKvmCpuidEntry {
            function: 0,
            index: 0,
            flags: KvmCpuidFlags::EMPTY,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: Padding::default(),
        };
        let mut raw_cpuid = RawCpuid::new();
        raw_cpuid.push(entry.clone()).unwrap();

        let mut_leaf = raw_cpuid.get_mut(0, 0).unwrap();
        assert_eq!(mut_leaf, &mut entry);
        let new_entry = RawKvmCpuidEntry {
            function: 0,
            index: 0,
            flags: KvmCpuidFlags::EMPTY,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: Padding::default(),
        };
        *mut_leaf = new_entry.clone();

        let leaf = raw_cpuid.get(0, 0).unwrap();
        assert_eq!(leaf, &new_entry);
    }

    #[test]
    fn kvm_set_cpuid() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let kvm_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();

        println!("kvm_cpuid:");
        for x in kvm_cpuid.as_slice() {
            println!("\t{x:?}");
        }

        let cpuid = RawCpuid::from(kvm_cpuid.clone());
        println!("cpuid:");
        for x in cpuid.iter() {
            println!("\t{x:?}");
        }

        let kvm_cpuid_2 = kvm_bindings::CpuId::from(cpuid);
        println!("kvm_cpuid_2:");
        for x in kvm_cpuid_2.as_slice() {
            println!("\t{x:?}");
        }
        assert_eq!(kvm_cpuid.as_slice(), kvm_cpuid_2.as_slice());

        vcpu.set_cpuid2(&kvm_cpuid_2).unwrap();

        let kvm_cpuid_3 = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
        println!("kvm_cpuid_3:");
        for x in kvm_cpuid_3.as_slice() {
            println!("\t{x:?}");
        }
    }

    #[test]
    fn between_kvm() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let kvm_cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let raw_cpuid = RawCpuid::from(kvm_cpuid.clone());
        let kvm_cpuid_2 = kvm_bindings::CpuId::from(raw_cpuid);

        assert_eq!(kvm_cpuid.as_slice(), kvm_cpuid_2.as_slice());
    }

    #[test]
    fn clone() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let kvm_cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let raw_cpuid = RawCpuid::from(kvm_cpuid);
        let cloned = raw_cpuid.clone();

        assert_eq!(raw_cpuid, cloned);
    }

    #[test]
    fn clone_zero() {
        let raw_cpuid = RawCpuid::new();
        let cloned = raw_cpuid.clone();

        assert_eq!(raw_cpuid, cloned);
    }
}
