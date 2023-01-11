// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::alloc::Layout;
use std::cmp::{Eq, PartialEq};
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::mem::{size_of, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use serde::{Deserialize, Serialize};

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
    /// Returns an entry for a given lead (function) and sub-leaf (index).
    ///
    /// Returning `None` if it is not present.
    #[inline]
    #[must_use]
    pub fn get(&self, leaf: u32, sub_leaf: u32) -> Option<&RawKvmCpuidEntry> {
        self.iter()
            .find(|entry| entry.function == leaf && entry.index == sub_leaf)
    }
    /// Resizes allocated memory.
    ///
    /// # Errors
    ///
    /// When failing to construct a layout.
    #[allow(clippy::cast_ptr_alignment, clippy::else_if_without_else)]
    fn resize(&mut self, n: u32) -> Result<(), RawCpuidResizeError> {
        // alloc
        if self.nent == 0 && n > 0 {
            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let new_len = unsafe { usize::try_from(n).unwrap_unchecked() };

            let new_layout =
                Layout::array::<RawKvmCpuidEntry>(new_len).map_err(RawCpuidResizeError)?;

            // SAFETY: Always safe.
            let new_ptr = unsafe { std::alloc::alloc(new_layout) };
            self.entries = match NonNull::new(new_ptr.cast::<RawKvmCpuidEntry>()) {
                Some(p) => p,
                None => std::alloc::handle_alloc_error(new_layout),
            };
        }
        // realloc
        else if self.nent > 0 && n > 0 {
            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let new_len = unsafe { usize::try_from(n).unwrap_unchecked() };

            let new_layout =
                Layout::array::<RawKvmCpuidEntry>(new_len).map_err(RawCpuidResizeError)?;

            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let len = unsafe { usize::try_from(self.nent).unwrap_unchecked() };

            let old_layout = Layout::array::<RawKvmCpuidEntry>(len).map_err(RawCpuidResizeError)?;
            let old_ptr = self.entries.as_ptr().cast::<u8>();
            // SAFETY: Always safe.
            let new_ptr = unsafe { std::alloc::realloc(old_ptr, old_layout, new_layout.size()) };

            self.entries = match NonNull::new(new_ptr.cast::<RawKvmCpuidEntry>()) {
                Some(p) => p,
                None => std::alloc::handle_alloc_error(new_layout),
            };
        }
        // dealloc
        else if self.nent > 0 && n == 0 {
            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let len = unsafe { usize::try_from(self.nent).unwrap_unchecked() };

            let old_layout = Layout::array::<RawKvmCpuidEntry>(len).map_err(RawCpuidResizeError)?;
            let old_ptr = self.entries.as_ptr().cast::<u8>();
            // SAFETY: Always safe.
            unsafe { std::alloc::dealloc(old_ptr, old_layout) };
            self.entries = NonNull::dangling();
        }
        self.nent = n;
        Ok(())
    }

    /// Pushes entry onto end.
    ///
    /// # Errors
    ///
    /// On resize failure.
    #[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
    #[inline]
    pub fn push(&mut self, entry: RawKvmCpuidEntry) -> Result<(), RawCpuidResizeError> {
        self.resize(self.nent + 1)?;

        // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
        // converted into it.
        let len = unsafe { usize::try_from(self.nent).unwrap_unchecked() };

        // SAFETY: Always safe.
        unsafe {
            std::ptr::write(self.entries.as_ptr().add(len), entry);
        }
        Ok(())
    }
    /// Pops entry from end.
    ///
    /// # Panics
    ///
    /// On allocation failure.
    #[inline]
    pub fn pop(&mut self) -> Option<RawKvmCpuidEntry> {
        (self.nent > 0).then(|| {
            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let len = unsafe { usize::try_from(self.nent).unwrap_unchecked() };
            // SAFETY: When `self.entries.as_ptr().add(u_nent)` contains a valid value.
            let rtn = unsafe { std::ptr::read(self.entries.as_ptr().add(len)) };

            // SAFETY: We check before `self.nent > 0` therefore unwrapping here is safe.
            let new_nent = unsafe { self.nent.checked_sub(1).unwrap_unchecked() };

            // Since we are decreasing the size `resize` should never panic.
            #[allow(clippy::unwrap_used)]
            self.resize(new_nent).unwrap();

            rtn
        })
    }
}

impl Clone for RawCpuid {
    #[allow(clippy::indexing_slicing)]
    #[inline]
    fn clone(&self) -> Self {
        let mut new_raw_cpuid = Self::new();

        // Since we are cloning an existing structure with this size, we can presume resizing to
        // this size is safe.
        #[allow(clippy::unwrap_used)]
        new_raw_cpuid.resize(self.nent).unwrap();

        for i in 0..self.nent {
            // SAFETY: `usize` will always be at least 32 bits, thus `u32` can always be safely
            // converted into it.
            let index = unsafe { usize::try_from(i).unwrap_unchecked() };

            new_raw_cpuid[index] = self[index].clone();
        }

        new_raw_cpuid
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
            // SAFETY: Always safe.
            unsafe {
                std::alloc::dealloc(
                    self.entries.as_ptr().cast::<u8>(),
                    Layout::array::<RawKvmCpuidEntry>(usize::try_from(self.nent).unwrap()).unwrap(),
                );
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

#[cfg(cpuid)]
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

#[cfg(cpuid)]
impl From<RawCpuid> for kvm_bindings::CpuId {
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn from(this: RawCpuid) -> Self {
        // SAFETY: Always safe.
        let cpuid_slice = unsafe {
            std::slice::from_raw_parts(this.entries.as_ptr(), usize::try_from(this.nent).unwrap())
        };

        // SAFETY: Always safe.
        let kvm_bindings_slice = unsafe { std::mem::transmute(cpuid_slice) };
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

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    #[cfg(cpuid)]
    use kvm_bindings::KVM_MAX_CPUID_ENTRIES;

    #[cfg(cpuid)]
    use super::*;

    #[cfg(cpuid)]
    #[test]
    fn kvm_set_cpuid() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let kvm_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();

        println!("kvm_cpuid:");
        for x in kvm_cpuid.as_slice() {
            println!("\t{:?}", x);
        }

        let cpuid = RawCpuid::from(kvm_cpuid.clone());
        println!("cpuid:");
        for x in cpuid.iter() {
            println!("\t{:?}", x);
        }

        let kvm_cpuid_2 = kvm_bindings::CpuId::from(cpuid);
        println!("kvm_cpuid_2:");
        for x in kvm_cpuid_2.as_slice() {
            println!("\t{:?}", x);
        }
        assert_eq!(kvm_cpuid.as_slice(), kvm_cpuid_2.as_slice());

        vcpu.set_cpuid2(&kvm_cpuid_2).unwrap();

        let kvm_cpuid_3 = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
        println!("kvm_cpuid_3:");
        for x in kvm_cpuid_3.as_slice() {
            println!("\t{:?}", x);
        }
    }
    #[cfg(cpuid)]
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
    #[cfg(cpuid)]
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
