// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// A type interface for a single bit.
#[derive(Debug, Clone)]
pub struct Bit<'a, T, const P: u8>(pub &'a T);

/// A type interface for a single bit.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct BitMut<'a, T, const P: u8>(pub &'a mut T);

/// Macro for defining `impl Display for Bit`.
macro_rules! bit_display {
    ($x:ty) => {
        impl<const P: u8> std::fmt::Display for Bit<'_, $x, P> {
            #[doc = concat!("
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                assert_eq!(Bit::<_,0>(&x).to_string(),true.to_string());
                assert_eq!(Bit::<_,1>(&x).to_string(),false.to_string());
                assert_eq!(Bit::<_,2>(&x).to_string(),true.to_string());
                ```
            ")]
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", bool::from(self))
            }
        }
    };
}

bit_display!(u128);
bit_display!(u64);
bit_display!(u32);
bit_display!(u16);
bit_display!(u8);

/// Macro for defining `impl Display for BitMut`.
macro_rules! bit_mut_display {
    ($x:ty) => {
        impl<const P: u8> std::fmt::Display for BitMut<'_, $x, P> {
            #[doc = concat!("
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                assert_eq!(BitMut::<_,0>(&mut x).to_string(),true.to_string());
                assert_eq!(BitMut::<_,1>(&mut x).to_string(),false.to_string());
                assert_eq!(BitMut::<_,2>(&mut x).to_string(),true.to_string());
                ```
            ")]
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", bool::from(self))
            }
        }
    };
}

bit_mut_display!(u128);
bit_mut_display!(u64);
bit_mut_display!(u32);
bit_mut_display!(u16);
bit_mut_display!(u8);

/// Macro for defining `impl Bit`.
macro_rules! bit {
    ($x:ty) => {
        impl<const P: u8> Bit<'_, $x, P> {
            pub const MASK: $x = 1 << P;

            #[doc = concat!("
                Returns the value of the bit.
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                assert_eq!(Bit::<_,0>(&x).read(),true);
                assert_eq!(Bit::<_,1>(&x).read(),false);
                assert_eq!(Bit::<_,2>(&x).read(),true);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn read(&self) -> bool {
                bool::from(self)
            }

            #[doc = concat!("
                Returns if the bit is 1.
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                assert_eq!(Bit::<_,0>(&x).is_on(),true);
                assert_eq!(Bit::<_,1>(&x).is_on(),false);
                assert_eq!(Bit::<_,2>(&x).is_on(),true);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn is_on(&self) -> bool {
                bool::from(self)
            }

            #[doc = concat!("
                Returns if the bit is 0.
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                assert_eq!(Bit::<_,0>(&x).is_off(),false);
                assert_eq!(Bit::<_,1>(&x).is_off(),true);
                assert_eq!(Bit::<_,2>(&x).is_off(),false);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn is_off(&self) -> bool {
                !bool::from(self)
            }
        }
    };
}

bit!(u128);
bit!(u64);
bit!(u32);
bit!(u16);
bit!(u8);

/// Macro for defining `impl BitMut`.
macro_rules! bit_mut {
    ($x:ty) => {
        impl<const P: u8> BitMut<'_, $x, P> {
            pub const MASK: $x = 1 << P;

            #[doc = concat!("
                Returns the value of the bit.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                assert_eq!(BitMut::<_,0>(&mut x).read(),true);
                assert_eq!(BitMut::<_,1>(&mut x).read(),false);
                assert_eq!(BitMut::<_,2>(&mut x).read(),true);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn read(&self) -> bool {
                bool::from(self)
            }

            #[doc = concat!("
                Alias for [`Self::set`].
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                BitMut::<_,0>(&mut x).write(false);
                assert_eq!(x,4);
                BitMut::<_,1>(&mut x).write(true);
                assert_eq!(x,6);
                BitMut::<_,2>(&mut x).write(false);
                assert_eq!(x,2);
                ```
            ")]
            #[inline]
            pub fn write(&mut self, x: bool) {
                self.set(x);
            }

            // These values are only evaluated at compile-time, thus a failure can only occur at
            // compile-time and would be immediately obvious. Thus it is safe to use arithmetic
            // here.
            #[doc = concat!("
                Set the bit to 1.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                BitMut::<_,0>(&mut x).on();
                assert_eq!(x,5);
                BitMut::<_,1>(&mut x).on();
                assert_eq!(x,7);
                BitMut::<_,2>(&mut x).on();
                assert_eq!(x,7);
                ```
            ")]
            #[allow(clippy::integer_arithmetic)]
            #[inline]
            pub fn on(&mut self) {
                *self.0 |= Self::MASK;
            }

            #[doc = concat!("
                Returns if the bit is 1.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                assert_eq!(BitMut::<_,0>(&mut x).is_on(),true);
                assert_eq!(BitMut::<_,1>(&mut x).is_on(),false);
                assert_eq!(BitMut::<_,2>(&mut x).is_on(),true);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn is_on(&self) -> bool {
                bool::from(self)
            }

            // These values are only evaluated at compile-time, thus a failure can only occur at
            // compile-time and would be immediately obvious. Thus it is safe to use arithmetic
            // here.
            #[doc = concat!("
                Set the bit to 0.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                BitMut::<_,0>(&mut x).off();
                assert_eq!(x,4);
                BitMut::<_,1>(&mut x).off();
                assert_eq!(x,4);
                BitMut::<_,2>(&mut x).off();
                assert_eq!(x,0);
                ```
            ")]
            #[allow(clippy::integer_arithmetic)]
            #[inline]
            pub fn off(&mut self) {
                *self.0 &= !Self::MASK;
            }

            #[doc = concat!("
                Returns if the bit is 0.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                assert_eq!(BitMut::<_,0>(&mut x).is_off(),false);
                assert_eq!(BitMut::<_,1>(&mut x).is_off(),true);
                assert_eq!(BitMut::<_,2>(&mut x).is_off(),false);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn is_off(&self) -> bool {
                !bool::from(self)
            }

            // These values are only evaluated at compile-time, thus a failure can only occur at
            // compile-time and would be immediately obvious. Thus it is safe to use arithmetic
            // here.
            #[doc = concat!("
                Flips the value of the bit.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                BitMut::<_,0>(&mut x).flip();
                assert_eq!(x,4);
                BitMut::<_,1>(&mut x).flip();
                assert_eq!(x,6);
                BitMut::<_,2>(&mut x).flip();
                assert_eq!(x,2);
                ```
            ")]
            #[allow(clippy::integer_arithmetic)]
            #[inline]
            pub fn flip(&mut self) {
                *self.0 ^= Self::MASK;
            }

            #[doc = concat!("
                Sets the bit.
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                BitMut::<_,0>(&mut x).set(false);
                assert_eq!(x,4);
                BitMut::<_,1>(&mut x).set(true);
                assert_eq!(x,6);
                BitMut::<_,2>(&mut x).set(false);
                assert_eq!(x,2);
                ```
            ")]
            #[inline]
            pub fn set(&mut self, x: bool) {
                if x {
                    self.on()
                } else {
                    self.off()
                }
            }
        }
    };
}

bit_mut!(u128);
bit_mut!(u64);
bit_mut!(u32);
bit_mut!(u16);
bit_mut!(u8);

/// Macro for defining `From` implementations on `Bit`.
macro_rules! bit_from {
    ($x:ty) => {
        // These values are only evaluated at compile-time, thus a failure can only occur at
        // compile-time and would be immediately obvious. Thus it is safe to use arithmetic here.
        #[allow(clippy::integer_arithmetic, clippy::as_conversions)]
        impl<const P: u8> From<&Bit<'_, $x, P>> for bool {
            #[doc = concat!("
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                let bit = Bit::<_,0>(&x);
                assert_eq!(bool::from(&bit),true);
                let bit = Bit::<_,1>(&x);
                assert_eq!(bool::from(&bit),false);
                let bit = Bit::<_,2>(&x);
                assert_eq!(bool::from(&bit),true);
                ```
            ")]
            #[inline]
            fn from(this: &Bit<'_, $x, P>) -> Self {
                (*this.0 & Bit::<$x, P>::MASK) != 0
            }
        }
    };
}
bit_from!(u128);
bit_from!(u64);
bit_from!(u32);
bit_from!(u16);
bit_from!(u8);

/// Macro for defining `From` implementations on `BitMut`.
macro_rules! bit_mut_from {
    ($x:ty) => {
        // These values are only evaluated at compile-time, thus a failure can only occur at
        // compile-time and would be immediately obvious. Thus it is safe to use arithmetic here.
        #[allow(clippy::integer_arithmetic, clippy::as_conversions)]
        impl<const P: u8> From<&BitMut<'_, $x, P>> for bool {
            #[doc = concat!("
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                let bit = BitMut::<_,0>(&mut x);
                assert_eq!(bool::from(&bit),true);
                let bit = BitMut::<_,1>(&mut x);
                assert_eq!(bool::from(&bit),false);
                let bit = BitMut::<_,2>(&mut x);
                assert_eq!(bool::from(&bit),true);
                ```
            ")]
            #[inline]
            fn from(this: &BitMut<'_, $x, P>) -> Self {
                (*this.0 & BitMut::<$x, P>::MASK) != 0
            }
        }
    };
}

bit_mut_from!(u128);
bit_mut_from!(u64);
bit_mut_from!(u32);
bit_mut_from!(u16);
bit_mut_from!(u8);

/// Macro for defining `PartiaEq` and `Eq` implementations on `Bit`.
macro_rules! bit_eq {
    ($x:ty) => {
        impl<const P: u8> PartialEq for Bit<'_, $x, P> {
            #[doc = concat!("
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                let y = 5", stringify!($x), ";
                let a = Bit::<_,0>(&x);
                let b = Bit::<_,0>(&y);

                assert_eq!(a,b);
                ```
            ")]
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                let a = bool::from(self);
                let b = bool::from(other);
                a == b
            }
        }
        impl<const P: u8> PartialEq<bool> for Bit<'_, $x, P> {
            #[doc = concat!("
                ```
                use bit_fields::Bit;
                let x = 5", stringify!($x), ";
                assert_eq!(Bit::<_,0>(&x),true);
                assert_eq!(Bit::<_,1>(&x),false);
                assert_eq!(Bit::<_,2>(&x),true);
                ```
            ")]
            #[inline]
            fn eq(&self, other: &bool) -> bool {
                bool::from(self) == *other
            }
        }
        impl<const P: u8> Eq for Bit<'_, $x, P> {}
    };
}

bit_eq!(u128);
bit_eq!(u64);
bit_eq!(u32);
bit_eq!(u16);
bit_eq!(u8);

/// Macro for defining `PartiaEq` and `Eq` implementations on `BitMut`.
macro_rules! bit_mut_eq {
    ($x:ty) => {
        impl<const P: u8> PartialEq for BitMut<'_, $x, P> {
            #[doc = concat!("
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                let mut y = 5", stringify!($x), ";
                let a = BitMut::<_,0>(&mut x);
                let b = BitMut::<_,0>(&mut y);

                assert_eq!(a,b);
                ```
            ")]
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                let a = bool::from(self);
                let b = bool::from(other);
                a == b
            }
        }
        impl<const P: u8> PartialEq<bool> for BitMut<'_, $x, P> {
            #[doc = concat!("
                ```
                use bit_fields::BitMut;
                let mut x = 5", stringify!($x), ";
                assert_eq!(BitMut::<_,0>(&mut x),true);
                assert_eq!(BitMut::<_,1>(&mut x),false);
                assert_eq!(BitMut::<_,2>(&mut x),true);
                ```
            ")]
            #[inline]
            fn eq(&self, other: &bool) -> bool {
                bool::from(self) == *other
            }
        }
        impl<const P: u8> Eq for BitMut<'_, $x, P> {}
    };
}

bit_mut_eq!(u128);
bit_mut_eq!(u64);
bit_mut_eq!(u32);
bit_mut_eq!(u16);
bit_mut_eq!(u8);
