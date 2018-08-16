use std::arch::x86_64::__cpuid as host_cpuid;
use std::slice;

#[derive(Debug, PartialEq)]
pub enum Error {
    NotSupported,
    BufferOverflow,
}

/// Register designations used to get/set specific register values
/// within the brand string buffer
pub enum Reg {
    EAX = 0,
    EBX = 1,
    ECX = 2,
    EDX = 3,
}

/// A CPUID brand string wrapper, providing some efficient manipulation
/// primitives. This is achieved by bypassing the O(n) indexing, heap
/// allocation, and the unicode checks done by std::string::String.
///
pub struct BrandString {
    /// Flattened buffer, holding an array of 32-bit register values
    /// Laid out like this:
    ///   reg_buf[0] = leaf_0x80000002.EAX
    ///   reg_buf[1] = leaf_0x80000002.EBX
    ///   reg_buf[2] = leaf_0x80000002.ECX
    ///   reg_buf[3] = leaf_0x80000002.EDX
    ///   reg_buf[4] = leaf_0x80000003.EAX
    ///   ...
    ///   reg_buf[10] = leaf_0x80000004.ECX
    ///   reg_buf[11] = leaf_0x80000004.EDX
    /// When seen as a byte-array, this buffer holds the ASCII-encoded
    /// CPU brand string.
    reg_buf: [u32; BrandString::REG_BUF_SIZE],

    /// Actual string length, in bytes.
    /// E.g. for "Intel CPU", this would be strlen("Intel CPU") == 9
    len: usize,
}

impl BrandString {
    /// Register buffer size (in number of registers)
    /// There are 3 leaves (0x800000002 through 0x80000004),
    /// each with 4 regs (EAX, EBX, ECX, EDX)
    const REG_BUF_SIZE: usize = 3 * 4;

    /// Max Brand string length, in bytes (also in chars, since it is ASCII-encoded)
    /// The string is NULL-terminated, so the max string length is actually one byte
    /// less than the buffer size in bytes
    const MAX_LEN: usize = Self::REG_BUF_SIZE * 4 - 1;

    /// Creates an empty brand string (0-initialized)
    ///
    fn new() -> Self {
        Self {
            reg_buf: [0; Self::REG_BUF_SIZE],
            len: 0,
        }
    }

    /// Creates a brand string, initialized from the CPUID leaves 0x80000002 through 0x80000004
    /// of the host CPU.
    ///
    pub fn from_host_cpuid() -> Result<Self, Error> {
        let mut this = Self::new();
        let mut cpuid_regs = unsafe { host_cpuid(0x80000000) };

        if cpuid_regs.eax < 0x80000004 {
            // Brand string not supported by the host CPU
            return Err(Error::NotSupported);
        }

        for leaf in 0x80000002..=0x80000004 {
            cpuid_regs = unsafe { host_cpuid(leaf) };
            this.set_reg_for_leaf(leaf, Reg::EAX, cpuid_regs.eax);
            this.set_reg_for_leaf(leaf, Reg::EBX, cpuid_regs.ebx);
            this.set_reg_for_leaf(leaf, Reg::ECX, cpuid_regs.ecx);
            this.set_reg_for_leaf(leaf, Reg::EDX, cpuid_regs.edx);
        }

        let mut len = Self::MAX_LEN;
        {
            let this_bytes = this.as_bytes();
            while this_bytes[len - 1] == 0 && len > 0 {
                len -= 1;
            }
        }
        this.len = len;

        Ok(this)
    }

    /// Creates a (custom) brand string, initialized from src.
    /// No checks are performed on the length of src or its contents
    /// (src should be an ASCII-encoded string).
    ///
    #[inline]
    pub fn from_bytes_unchecked(src: &[u8]) -> Self {
        let mut this = Self::new();
        this.len = src.len();
        this.as_bytes_mut()[..src.len()].copy_from_slice(src);
        this
    }

    /// Returns the given register value for the given CPUID leaf.
    ///   leaf must be between 0x80000002 and 0x80000004
    #[inline]
    pub fn get_reg_for_leaf(&self, leaf: u32, reg: Reg) -> u32 {
        // It's ok not to validate parameters here, leaf and reg should
        // both be compile-time constants. If there's something wrong with them,
        // that's a programming error and we should panic anyway.
        self.reg_buf[(leaf - 0x80000002) as usize * 4 + reg as usize]
    }

    /// Sets the value for the given leaf/register pair
    ///   leaf must be between 0x80000002 and 0x80000004
    #[inline]
    pub fn set_reg_for_leaf(&mut self, leaf: u32, reg: Reg, val: u32) {
        // It's ok not to validate parameters here, leaf and reg should
        // both be compile-time constants. If there's something wrong with them,
        // that's a programming error and we should panic anyway.
        self.reg_buf[(leaf - 0x80000002) as usize * 4 + reg as usize] = val;
    }

    /// Get an immutable u8 slice view into the brand string buffer
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // This is actually safe, because self.reg_buf has a fixed, known size,
        // and also there's no risk of misalignment, since we're downgrading
        // alignment constraints from dword to byte.
        unsafe { slice::from_raw_parts(self.reg_buf.as_ptr() as *const u8, Self::REG_BUF_SIZE * 4) }
    }

    /// Get a mutable u8 slice view into the brand string buffer
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self.reg_buf.as_mut_ptr() as *mut u8, Self::REG_BUF_SIZE * 4)
        }
    }

    /// Appends src to the brand string.
    /// If there isn't enough room to append src, Error::BufferOverflow is returned.
    ///
    pub fn push_bytes(&mut self, src: &[u8]) -> Result<(), Error> {
        if src.len() > Self::MAX_LEN - self.len {
            // No room to push all of src.
            return Err(Error::BufferOverflow);
        }
        let start = self.len;
        let count = src.len();
        self.len += count;
        self.as_bytes_mut()[start..(start + count)].copy_from_slice(src);
        Ok(())
    }

    /// Checks if src is a prefix of the brand string
    ///
    pub fn starts_with(&self, src: &[u8]) -> bool {
        if src.len() > Self::MAX_LEN {
            return false;
        }
        &self.as_bytes()[..src.len()] == src
    }

    /// Searches the brand string for the CPU frequency data it may contain (e.g. 4.01GHz),
    /// and, if found, returns it as an u8 slice.
    /// Basically, we're implementing a search for this regex: [0-9.]+[MG]Hz
    ///
    pub fn find_freq(&self) -> Option<&[u8]> {
        let mut it = self
            .as_bytes()
            .iter()
            .rev()
            .skip(self.as_bytes().len() - self.len)
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
            return None;
        }

        Some(&self.as_bytes()[freq_start..=freq_end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brand_string() {
        #[inline]
        fn pack_u32(src: &[u8]) -> u32 {
            assert!(src.len() >= 4);
            src[0] as u32
                | ((src[1] as u32) << 8)
                | ((src[2] as u32) << 16)
                | ((src[3] as u32) << 24)
        }

        const TEST_STR: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut bstr = BrandString::from_bytes_unchecked(TEST_STR);

        // Test the immutable bitwise casts
        //
        {
            for i in 0_usize..=1_usize {
                let eax_offs = (4 * 4) * i + 0;
                let ebx_offs = (4 * 4) * i + 4;
                let ecx_offs = (4 * 4) * i + 8;
                let edx_offs = (4 * 4) * i + 12;
                assert_eq!(
                    bstr.get_reg_for_leaf(0x80000002 + i as u32, Reg::EAX),
                    pack_u32(&TEST_STR[eax_offs..(eax_offs + 4)])
                );
                assert_eq!(
                    bstr.get_reg_for_leaf(0x80000002 + i as u32, Reg::EBX),
                    pack_u32(&TEST_STR[ebx_offs..(ebx_offs + 4)])
                );
                assert_eq!(
                    bstr.get_reg_for_leaf(0x80000002 + i as u32, Reg::ECX),
                    pack_u32(&TEST_STR[ecx_offs..(ecx_offs + 4)])
                );
                assert_eq!(
                    bstr.get_reg_for_leaf(0x80000002 + i as u32, Reg::EDX),
                    pack_u32(&TEST_STR[edx_offs..(edx_offs + 4)])
                );
            }
        }

        // Test find_freq() failure path
        //
        assert!(bstr.find_freq().is_none());

        // Test mutable bitwise casting and finding the frequency substring
        //
        bstr.set_reg_for_leaf(0x80000003, Reg::EBX, pack_u32(b"5.20"));
        bstr.set_reg_for_leaf(0x80000003, Reg::ECX, pack_u32(b"GHz "));
        assert_eq!(bstr.find_freq().unwrap(), b"5.20GHz");

        // Test BrandString::starts_with()
        //
        assert_eq!(bstr.starts_with(b"012345"), true);
        assert_eq!(bstr.starts_with(b"01234X"), false);
        assert_eq!(bstr.starts_with(b"X01234"), false);

        // Test BrandString::push_bytes()
        //
        bstr = BrandString::new();
        bstr.push_bytes(b"Hello").unwrap();
        bstr.push_bytes(b", world!").unwrap();
        assert!(bstr.starts_with(b"Hello, world!"));

        // Test BrandString::push_bytes() failure path
        //
        let _overflow: [u8; 50] = [b'a'; 50];
        assert_eq!(
            bstr.push_bytes(&_overflow).unwrap_err(),
            Error::BufferOverflow
        );

        // Test BrandString::from_host_cpuid() and get_reg_for_leaf()
        //
        match BrandString::from_host_cpuid() {
            Ok(bstr) => {
                for leaf in 0x80000002..=0x80000004_u32 {
                    let host_regs = unsafe { host_cpuid(leaf) };
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::EAX), host_regs.eax);
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::EBX), host_regs.ebx);
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::ECX), host_regs.ecx);
                    assert_eq!(bstr.get_reg_for_leaf(leaf, Reg::EDX), host_regs.edx);
                }
            }
            Err(Error::NotSupported) => {
                // from_host_cpuid() should only fail if the host CPU doesn't support
                // CPUID leaves up to 0x80000004, so let's make sure that's what happened.
                let host_regs = unsafe { host_cpuid(0x80000000) };
                assert!(host_regs.eax < 0x80000004);
            }
            Err(_) => assert!(false),
        }
    }
}
