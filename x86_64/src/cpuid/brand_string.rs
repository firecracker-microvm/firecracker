use super::host_cpuid;
use std::cmp;
use std::mem;
use std::ptr;
use std::str;

pub const BRAND_STRING_MIN_LEAF: u32 = 0x80000002;
pub const BRAND_STRING_MAX_LEAF: u32 = 0x80000004;
pub const BRAND_STRING_LEAF_COUNT: u32 = BRAND_STRING_MAX_LEAF - BRAND_STRING_MIN_LEAF + 1;

pub const BRAND_STRING_MAX_LEN: usize =
    BRAND_STRING_LEAF_COUNT as usize * mem::size_of::<BrandStringRegs>();

#[derive(Debug)]
pub enum Error {
    BrandStringNotSupported,
    FreqNotFound,
}

// Defining our own regs structure here, since we'll be relying on
// precise struct sizing. Also, technically, the registers used by
// the brand string leaves are a subset of the CPUID registers.
#[repr(C)]
pub struct BrandStringRegs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// A CPUID brand string wrapper, providing some efficient manipulation
/// primitives. This is achieved by bypassing the O(n) indexing, heap
/// allocation, and the unicode checks done by std::string::String.
///
pub struct BrandString {
    bytes: [u8; BRAND_STRING_MAX_LEN],
    len: usize,
}

impl BrandString {
    /// Creates an empty brand string (0-initialized)
    ///
    fn new() -> Self {
        Self {
            bytes: [0; BRAND_STRING_MAX_LEN],
            len: 0,
        }
    }

    /// Creates a brand string, initialized from the CPUID leaves
    /// 0x80000002 through 0x80000004, of the host CPU
    ///
    pub fn from_host_cpuid() -> Result<Self, Error> {
        let mut this = Self::new();
        let mut cpuid_regs = host_cpuid(0x80000000);

        if cpuid_regs.eax < BRAND_STRING_MAX_LEAF {
            return Err(Error::BrandStringNotSupported);
        }

        for i in 0..BRAND_STRING_LEAF_COUNT {
            cpuid_regs = host_cpuid(BRAND_STRING_MIN_LEAF + i);
            let this_regs = this.borrow_mut_regs_for_leaf(BRAND_STRING_MIN_LEAF + i);
            this_regs.eax = cpuid_regs.eax;
            this_regs.ebx = cpuid_regs.ebx;
            this_regs.ecx = cpuid_regs.ecx;
            this_regs.edx = cpuid_regs.edx;
        }

        this.len = this.bytes.len();
        while this.bytes[this.len - 1] == 0 && this.len > 0 {
            this.len -= 1;
        }

        Ok(this)
    }

    /// Creates a (custom) brand string, initialized from src
    /// If src.len() exceeds BRAND_STRING_MAX_LEN, the brand string
    /// will contain only the fist BRAND_STRING_MAX_LEN-1 chars from src
    /// (the brand string needs to be NULL-terminated)
    ///
    pub fn from_str(src: &str) -> Self {
        let mut this = Self::new();

        this.len = cmp::min(src.len(), BRAND_STRING_MAX_LEN - 1);
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), this.bytes.as_mut_ptr(), this.len);
        }
        this
    }

    /// Provides a raw, register-level view into the brand string.
    /// The register values are the those that would be set by
    /// calling CPUID with EAX=leaf, on a CPU with self as brand string
    ///
    /// Note: this transformation is provided only for the caller's
    /// convenience. No data is copied.
    #[inline]
    pub fn borrow_regs_for_leaf(&self, leaf: u32) -> &BrandStringRegs {
        if leaf < BRAND_STRING_MIN_LEAF || leaf > BRAND_STRING_MAX_LEAF {
            panic!("Invalid CPUID brand string leaf: {}", leaf);
        }
        unsafe {
            mem::transmute::<*const u8, &BrandStringRegs>(self.bytes.as_ptr().offset(
                ((leaf - BRAND_STRING_MIN_LEAF) * mem::size_of::<BrandStringRegs>() as u32)
                    as isize,
            ))
        }
    }

    /// Same as borrow_regs_for_leaf(), but providing a mutable reference
    /// to the inner registers.
    #[inline]
    pub fn borrow_mut_regs_for_leaf(&mut self, leaf: u32) -> &mut BrandStringRegs {
        if leaf < BRAND_STRING_MIN_LEAF || leaf > BRAND_STRING_MAX_LEAF {
            panic!("Invalid CPUID brand string leaf: {}", leaf);
        }
        unsafe {
            mem::transmute::<*mut u8, &mut BrandStringRegs>(self.bytes.as_mut_ptr().offset(
                ((leaf - BRAND_STRING_MIN_LEAF) * mem::size_of::<BrandStringRegs>() as u32)
                    as isize,
            ))
        }
    }

    /// Appends src to the brand string.
    /// If there isn't enough room to append src, this operation silently fails,
    /// and the brand string remains unchanged.
    ///
    pub fn push_str(&mut self, src: &str) {
        if src.len() > self.bytes.len() - 1 - self.len {
            // No room to push all of src. Fail silently
            return;
        }
        unsafe {
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.bytes.as_mut_ptr().offset(self.len as isize),
                src.len(),
            );
        }
        self.len += src.len();
    }

    /// Checks if src is a prefix of the brand string
    ///
    pub fn starts_with(&self, src: &str) -> bool {
        if src.len() > BRAND_STRING_MAX_LEN - 1 {
            return false;
        }
        self.bytes[..src.len()] == src.as_bytes()[..src.len()]
    }

    /// Searches the brand string for the CPU frequency data
    /// it may contain (e.g. 4.01GHz), and, if found,
    /// returns it as a str slice.
    /// No data is copied; the returned value is an immutable view
    /// into the brand string buffer.
    ///
    pub fn borrow_freq_str(&self) -> Result<&str, Error> {
        let mut it = self
            .bytes
            .iter()
            .rev()
            .skip(self.bytes.len() - self.len)
            .enumerate();
        let mut freq_start = 0_usize;
        let mut freq_end = 0_usize;

        while freq_start == 0 {
            match it.next() {
                Some((i, &b'z')) => freq_end = self.len - i - 1,
                Some((_, _)) => continue,
                None => break,
            }
            match it.next() {
                Some((_, &b'H')) => {}
                Some((_, _)) => continue,
                None => break,
            }
            match it.next() {
                Some((_, &ch)) => {
                    if ch != b'M' && ch != b'G' {
                        continue;
                    }
                }
                None => break,
            }
            while let Some((i, &ch)) = it.next() {
                if ch == b'.' || (ch >= b'0' && ch <= b'9') {
                    freq_start = self.len - i - 1;
                    continue;
                }
                break;
            }
        }

        if freq_start == 0 {
            return Err(Error::FreqNotFound);
        }

        unsafe { Ok(str::from_utf8_unchecked(&self.bytes[freq_start..=freq_end])) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_brand_string() {
        #[inline]
        fn str_to_u32(src: &str) -> u32 {
            assert!(src.len() >= 4);
            unsafe { ptr::read(src.as_ptr() as *const u32) }
        }

        const TEST_STR: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut bstr = BrandString::from_str(TEST_STR);

        // Test the immutable bitwise casts
        //
        {
            for i in 0_usize..=1_usize {
                let leaf_regs = bstr.borrow_regs_for_leaf(BRAND_STRING_MIN_LEAF + i as u32);
                let eax_offs = mem::size_of::<BrandStringRegs>() * i
                    + &leaf_regs.eax as *const _ as usize
                    - leaf_regs as *const _ as usize;
                let ebx_offs = mem::size_of::<BrandStringRegs>() * i
                    + &leaf_regs.ebx as *const _ as usize
                    - leaf_regs as *const _ as usize;
                let ecx_offs = mem::size_of::<BrandStringRegs>() * i
                    + &leaf_regs.ecx as *const _ as usize
                    - leaf_regs as *const _ as usize;
                let edx_offs = mem::size_of::<BrandStringRegs>() * i
                    + &leaf_regs.edx as *const _ as usize
                    - leaf_regs as *const _ as usize;
                assert_eq!(
                    leaf_regs.eax,
                    str_to_u32(&TEST_STR[eax_offs..(eax_offs + 4)])
                );
                assert_eq!(
                    leaf_regs.ebx,
                    str_to_u32(&TEST_STR[ebx_offs..(ebx_offs + 4)])
                );
                assert_eq!(
                    leaf_regs.ecx,
                    str_to_u32(&TEST_STR[ecx_offs..(ecx_offs + 4)])
                );
                assert_eq!(
                    leaf_regs.edx,
                    str_to_u32(&TEST_STR[edx_offs..(edx_offs + 4)])
                );
            }
        }

        // Test mutable bitwise casting and finding the frequency substring
        //
        {
            let mut_leaf_regs = bstr.borrow_mut_regs_for_leaf(BRAND_STRING_MIN_LEAF + 1);
            mut_leaf_regs.ebx = str_to_u32("5.20");
            mut_leaf_regs.ecx = str_to_u32("GHz ");
        }
        {
            assert_eq!(bstr.borrow_freq_str().unwrap(), "5.20GHz");
        }

        // Test BrandString::starts_with()
        //
        assert_eq!(bstr.starts_with("012345"), true);
        assert_eq!(bstr.starts_with("01234X"), false);
        assert_eq!(bstr.starts_with("X01234"), false);

        // Test BrandString::push_str()
        //
        bstr = BrandString::new();
        bstr.push_str("Hello");
        bstr.push_str(", world!");
        assert!(bstr.starts_with("Hello, world!"));

        // Test BrandString::from_host_cpuid() and borrow_regs_for_leaf()
        //
        match BrandString::from_host_cpuid() {
            Ok(bstr) => {
                for i in 0..BRAND_STRING_LEAF_COUNT {
                    let leaf_regs = bstr.borrow_regs_for_leaf(BRAND_STRING_MIN_LEAF + i);
                    let host_regs = host_cpuid(BRAND_STRING_MIN_LEAF + i);
                    assert_eq!(leaf_regs.eax, host_regs.eax);
                    assert_eq!(leaf_regs.ebx, host_regs.ebx);
                    assert_eq!(leaf_regs.ecx, host_regs.ecx);
                    assert_eq!(leaf_regs.edx, host_regs.edx);
                }
            }
            Err(Error::BrandStringNotSupported) => {
                let host_regs = host_cpuid(0x80000000);
                assert!(host_regs.eax >= BRAND_STRING_MAX_LEAF);
            }
            Err(_) => assert!(false),
        }
    }
}
