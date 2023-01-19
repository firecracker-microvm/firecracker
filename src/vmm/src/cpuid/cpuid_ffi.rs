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

use serde::{Deserialize, Serialize};

use crate::cpuid::{CpuidEntry, CpuidKey};

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
    #[allow(clippy::transmute_ptr_to_ptr)]
    #[inline]
    fn get(&self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&CpuidEntry> {
        let entry_opt = self
            .iter()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);

        entry_opt.map(|entry| {
            // SAFETY: The `RawKvmCpuidEntry` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &[u8; size_of::<RawKvmCpuidEntry>()] = transmute(entry);
                let arr2: &[u8; size_of::<CpuidEntry>()] =
                    arr.get_unchecked(8..28).try_into().unwrap_unchecked();
                transmute::<_, &CpuidEntry>(arr2)
            }
        })
    }

    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr)]
    #[inline]
    fn get_mut(&mut self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&mut CpuidEntry> {
        let entry_opt = self
            .iter_mut()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);
        entry_opt.map(|entry| {
            // SAFETY: The `RawKvmCpuidEntry` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &mut [u8; size_of::<RawKvmCpuidEntry>()] = transmute(entry);
                let arr2: &mut [u8; size_of::<CpuidEntry>()] =
                    arr.get_unchecked_mut(8..28).try_into().unwrap_unchecked();
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

    /// Pushes entry onto end.
    ///
    /// # Errors
    ///
    /// On resize failure.
    #[allow(clippy::cast_ptr_alignment)]
    #[inline]
    pub fn push(&mut self, entry: RawKvmCpuidEntry) -> Result<(), RawCpuidPushError> {
        let new = self
            .nent
            .checked_add(1)
            .ok_or(RawCpuidPushError::Overflow)?;
        let new_layout =
            // SAFETY: Only 64-bit platforms are supported and converting `u32` to `usize` can only
            // fail on 16-bit platforms.
            Layout::array::<RawKvmCpuidEntry>(unsafe { usize::try_from(new).unwrap_unchecked() })
                .map_err(RawCpuidPushError::Layout)?;
        // SAFETY: Only 64-bit platforms are supported and converting `u32` to `usize` can only fail
        // on 16-bit platforms.
        let nent_usize = unsafe { usize::try_from(self.nent).unwrap_unchecked() };

        let new_ptr = if self.nent == 0 {
            // SAFETY: Always safe.
            unsafe { std::alloc::alloc(new_layout) }
        } else {
            let old_layout =
                Layout::array::<RawKvmCpuidEntry>(nent_usize).map_err(RawCpuidPushError::Layout)?;
            let old_ptr = self.entries.as_ptr().cast::<u8>();
            // SAFETY: Always safe.
            unsafe { std::alloc::realloc(old_ptr, old_layout, new_layout.size()) }
        };

        self.entries = match NonNull::new(new_ptr.cast::<RawKvmCpuidEntry>()) {
            Some(ptr) => ptr,
            None => std::alloc::handle_alloc_error(new_layout),
        };

        // SAFETY: `self.entries.as_ptr().add(net)` is within the allocated range. Only 64-bit
        // platforms are supported and converting `u32` to `usize` can only fail on 16-bit
        // platforms.
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
            // SAFETY: We know the pointer is valid. Only 64-bit platforms are supported and
            // converting `u32` to `usize` can only fail on 16-bit platforms.
            unsafe {
                Some(std::ptr::read(
                    self.entries
                        .as_ptr()
                        .add(usize::try_from(self.nent).unwrap_unchecked()),
                ))
            }
        } else {
            None
        }
    }
}

#[allow(
    clippy::cast_ptr_alignment,
    clippy::unwrap_used,
    clippy::manual_let_else
)]
impl Clone for RawCpuid {
    #[inline]
    fn clone(&self) -> Self {
        if self.nent == 0 {
            Self::new()
        } else {
            // SAFETY: Only 64-bit platforms are supported and converting `u32` to `usize` can only
            // fail on 16-bit platforms.
            let nent_usize = unsafe { usize::try_from(self.nent).unwrap_unchecked() };
            let layout = Layout::array::<RawKvmCpuidEntry>(nent_usize).unwrap();
            // SAFETY: Always safe.
            let ptr = unsafe { std::alloc::alloc(layout) };
            let entries = match NonNull::new(ptr.cast::<RawKvmCpuidEntry>()) {
                Some(p) => p,
                None => std::alloc::handle_alloc_error(layout),
            };
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

impl serde::Serialize for RawCpuid {
    #[allow(clippy::indexing_slicing)]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
        // converted into it.
        let len = unsafe { usize::try_from(self.nent).unwrap_unchecked() };
        let mut seq = serializer.serialize_seq(Some(len))?;
        for i in 0..len {
            seq.serialize_element(&self[i])?;
        }
        seq.end()
    }
}

/// Unit struct used in the `serde::de::Visitor` implementation of `RawCpuid`.
struct RawCpuidVisitor;

impl<'de> serde::de::Visitor<'de> for RawCpuidVisitor {
    type Value = RawCpuid;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expected sequence of RawKvmCpuidEntry")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut entries = Vec::new();
        while let Some(next) = seq.next_element::<RawKvmCpuidEntry>()? {
            entries.push(next);
        }
        Ok(Self::Value::from(entries))
    }
}

impl<'de> serde::Deserialize<'de> for RawCpuid {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(RawCpuidVisitor)
    }
}

impl PartialEq for RawCpuid {
    #[allow(clippy::indexing_slicing)]
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        if self.nent == other.nent {
            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let n = unsafe { usize::try_from(self.nent).unwrap_unchecked() };
            for i in 0..n {
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

// SAFETY: Always safe.
unsafe impl Send for RawCpuid {}

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
            let layout = Layout::array::<RawKvmCpuidEntry>(usize::try_from(cap).unwrap()).unwrap();
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
        // SAFETY: Always safe.
        unsafe {
            std::slice::from_raw_parts(self.entries.as_ptr(), usize::try_from(self.nent).unwrap())
        }
    }
}

impl DerefMut for RawCpuid {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: Always safe.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.entries.as_ptr(),
                usize::try_from(self.nent).unwrap(),
            )
        }
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
        // SAFETY: Always safe.
        let cpuid_slice = unsafe {
            std::slice::from_raw_parts(this.entries.as_ptr(), usize::try_from(this.nent).unwrap())
        };

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

impl<const N: usize> serde::Serialize for Padding<N> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_unit_struct("Padding")
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for Padding<N> {
    #[inline]
    fn deserialize<D>(_deserializer: D) -> Result<Padding<N>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Padding(MaybeUninit::uninit()))
    }
}

impl<const N: usize> PartialEq for Padding<N> {
    #[inline]
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<const N: usize> Eq for Padding<N> {}

bit_fields::bitfield!(
    /// Definitions from `kvm/arch/x86/include/uapi/asm/kvm.h
    KvmCpuidFlags,
    u32,
    {
        /// Indicates if the `index` field is used for indexing sub-leaves (if false, this CPUID leaf
        /// has no subleaves).
        significant_index: 0,
        /// Deprecated.
        stateful_func: 1,
        /// Deprecated.
        state_read_next: 2,
    }
);

/// CPUID entry (a mimic of <https://elixir.bootlin.com/linux/v5.10.129/source/arch/x86/include/uapi/asm/kvm.h#L232>).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

    use super::*;
    use crate::cpuid::{CpuidRegisters, CpuidTrait};

    #[test]
    fn raw_cpuid_resize_error_debug() {
        let layout_error = std::alloc::Layout::array::<u8>(usize::MAX).unwrap_err();
        assert_eq!(
            format!("{:?}", RawCpuidResizeError(layout_error)),
            "RawCpuidResizeError(LayoutError)"
        );
    }
    #[test]
    fn raw_cpuid_resize_error_display() {
        let layout_error = std::alloc::Layout::array::<u8>(usize::MAX).unwrap_err();
        assert_eq!(
            RawCpuidResizeError(layout_error).to_string(),
            "Failed to resize: invalid parameters to Layout::from_size_align"
        );
    }

    #[test]
    fn raw_cpuid_debug() {
        let mut raw_cpuid = RawCpuid::new();
        raw_cpuid
            .push(RawKvmCpuidEntry {
                function: 0,
                index: 0,
                flags: KvmCpuidFlags::empty(),
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: Padding::default(),
            })
            .unwrap();

        assert_eq!(
            format!("{raw_cpuid:?}"),
            format!(
                "RawCpuid {{ nent: 1, padding: Padding(core::mem::maybe_uninit::MaybeUninit<[u8; \
                 4]>), entries: {:?}, _marker: PhantomData<vmm::cpuid::cpuid_ffi::RawKvmCpuidEntry> }}",
                raw_cpuid.entries
            )
        );
    }

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
                flags: KvmCpuidFlags::empty(),
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
                flags: KvmCpuidFlags::empty(),
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
                flags: KvmCpuidFlags::empty(),
                result: set_result
            }
        );
    }

    #[test]
    fn raw_cpuid_get_mut() {
        let mut entry = RawKvmCpuidEntry {
            function: 0,
            index: 0,
            flags: KvmCpuidFlags::empty(),
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
            flags: KvmCpuidFlags::empty(),
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
}
