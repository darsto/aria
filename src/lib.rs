// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

//! ARIA cipher in Rust. This is an amateur implementation. Use at your risk.
//! See [`imp`] for the actual cipher implementation.

mod imp;

use std::mem::MaybeUninit;
use std::ptr::addr_of_mut;

pub trait BlockExt: AsRef<[u8; 16]> + From<[u8; 16]> + Sized {
    /// Creates a Block from the provided byte slice. This performs a memcpy.
    /// Only up to 16 bytes from the slice are copied. If the slice is even
    /// smaller, the rest of the Block is filled with zeroes
    fn new<T: AsRef<[u8]>>(value: T) -> Self {
        let mut arr: MaybeUninit<[u8; 16]> = MaybeUninit::uninit();
        let arr_ptr = arr.as_mut_ptr() as *mut u8;
        let src_len: usize = std::cmp::min(value.as_ref().len(), 16);
        // SAFETY: We're writing the whole Block, just avoiding the unnecesary
        // zero-initialization in the beginning.
        let arr = unsafe {
            arr_ptr.copy_from_nonoverlapping(value.as_ref().as_ptr(), src_len);
            arr_ptr.add(src_len).write_bytes(0, 16 - src_len);
            arr.assume_init()
        };
        Self::from(arr)
    }

    fn try_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        let bytes = self.as_ref();
        // find a smaller zero-terminated slice
        let real_len = bytes.iter().position(|&e| e == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[0..real_len])
    }

    /// Creates an array of Block-s from the provided byte slice. Up to N*16 bytes
    /// will be memcpied from the provided slice. If the slice is even smaller, the
    /// remaining Block-s are filled with zeroes
    fn arr_from_slice<T: AsRef<[u8]>, const N: usize>(bytes: T) -> [Self; N] {
        core::array::from_fn(|i| {
            let slice = if i * 16 < bytes.as_ref().len() {
                &bytes.as_ref()[i * 16..]
            } else {
                &[]
            };
            Self::new(slice)
        })
    }
}

/// A 16-byte Block of data to be ciphered
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Block([u8; 16]);

impl BlockExt for Block {}

impl AsRef<[u8; 16]> for Block {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsMut<[u8; 16]> for Block {
    fn as_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

impl From<[u8; 16]> for Block {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

fn slice_u32_to_u8(input: &[u32]) -> &[u8] {
    // SAFETY: We're casting [u32] to exact-length [u8], which is always safe
    unsafe { std::slice::from_raw_parts(input.as_ptr() as *const u8, input.len() * 4) }
}

fn slice_u32_to_u8_mut(input: &mut [u32]) -> &mut [u8] {
    // SAFETY: We're casting [u32] to exact-length [u8], which is always safe
    unsafe { std::slice::from_raw_parts_mut(input.as_ptr() as *mut u8, input.len() * 4) }
}

pub trait BlockSlice {
    fn try_as_str(&self) -> Result<&str, std::str::Utf8Error>;
    fn as_bytes(&self) -> &[u8];
    fn as_bytes_mut(&mut self) -> &mut [u8];
}

impl<T: AsRef<[u8; 16]>> BlockSlice for [T] {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: The Block is just a wrapper over 16 bytes and has no padding.
        // A slice of Block is always just a contiguous piece of memory, so it's
        // always safe to cast it to &[u8]
        unsafe { std::slice::from_raw_parts(self.as_ptr() as *const u8, self.len() * 16) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: The Block is just a wrapper over 16 bytes and has no padding.
        // A slice of Block is always just a contiguous piece of memory, so it's
        // always safe to cast it to &[u8]
        unsafe { std::slice::from_raw_parts_mut(self.as_ptr() as *mut u8, self.len() * 16) }
    }

    fn try_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        let bytes = self.as_bytes();
        // find a smaller zero-terminated slice
        let real_len = bytes.iter().position(|&e| e == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[0..real_len])
    }
}

/// Source key for the cipher. This can be later expanded into an [`ExpandedKey`]
/// used for encryption, which can be later derived into a [`DecryptKey`]
#[repr(C, align(8))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Key {
    /// 256-bit key, with trailing zeroes if needed
    data: [u32; 8],
    /// Original key length
    len: KeyLen,
}

impl Key {
    /// Convert a Key into an [`ExpandedKey`] used for actual encryption
    pub fn expand(&self) -> ExpandedKey {
        let mut expkey = match &self.len {
            KeyLen::K256 => ExpandedKey::K256([0u32; 0x44]),
            KeyLen::K192 => ExpandedKey::K192([0u32; 0x3c]),
            KeyLen::K128 => ExpandedKey::K128([0u32; 0x34]),
        };

        imp::expand_key(expkey.as_mut_slice(), &self.data);
        expkey
    }

    /// Get a byte slice to the internal key byte slice
    pub fn as_bytes(&self) -> &[u8] {
        slice_u32_to_u8(&self.data)
    }

    /// Get a mutable byte slice to the internal key byte slice
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        slice_u32_to_u8_mut(&mut self.data)
    }
}

/// Try to create a Key from the given slice. This succeeds for slice length
/// 16, 24, and 32. For all other lengths this return Err. For non-fallible
/// variants of this, there is `From<[u8; 32]>`, `From<[u8; 24]>`, and
/// `From<[u8; 16]>`.
impl TryFrom<&[u8]> for Key {
    type Error = ();
    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(keylen) = KeyLen::try_from(src.len()) {
            let mut key: MaybeUninit<Key> = MaybeUninit::uninit();
            let keyptr = key.as_mut_ptr();

            // SAFETY: We're always writing the full Key, just avoiding the unnecesary
            // zero-initialization in the beginning.
            unsafe {
                let data_ptr = addr_of_mut!((*keyptr).data) as *mut u8;
                let src_len = usize::from(keylen);
                data_ptr.copy_from_nonoverlapping(src.as_ptr(), src_len);
                data_ptr.add(src_len).write_bytes(0, 32 - src_len);
                addr_of_mut!((*keyptr).len).write(keylen);
                Ok(key.assume_init())
            }
        } else {
            Err(())
        }
    }
}

impl From<[u8; 32]> for Key {
    fn from(data: [u8; 32]) -> Self {
        // SAFETY: We're always constructing a 32-byte-long key, which always succeeds
        unsafe { Self::try_from(data.as_slice()).unwrap_unchecked() }
    }
}

impl From<[u8; 24]> for Key {
    fn from(data: [u8; 24]) -> Self {
        // SAFETY: We're always constructing a 24-byte-long key, which always succeeds
        unsafe { Self::try_from(data.as_slice()).unwrap_unchecked() }
    }
}

impl From<[u8; 16]> for Key {
    fn from(data: [u8; 16]) -> Self {
        // SAFETY: We're always constructing a 16-byte-long key, which always succeeds
        unsafe { Self::try_from(data.as_slice()).unwrap_unchecked() }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLen {
    K256,
    K192,
    K128,
}

impl TryFrom<usize> for KeyLen {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(match value {
            32 => Self::K256,
            24 => Self::K192,
            16 => Self::K128,
            _ => {
                return Err(());
            }
        })
    }
}

impl From<KeyLen> for usize {
    fn from(val: KeyLen) -> Self {
        match val {
            KeyLen::K256 => 32,
            KeyLen::K192 => 24,
            KeyLen::K128 => 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpandedKey {
    K256([u32; 0x44]),
    K192([u32; 0x3c]),
    K128([u32; 0x34]),
}

impl ExpandedKey {
    fn as_slice(&self) -> &[u32] {
        match self {
            ExpandedKey::K256(s) => s,
            ExpandedKey::K192(s) => s,
            ExpandedKey::K128(s) => s,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u32] {
        match self {
            ExpandedKey::K256(s) => s,
            ExpandedKey::K192(s) => s,
            ExpandedKey::K128(s) => s,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        slice_u32_to_u8(self.as_slice())
    }

    pub fn encrypt<I: AsRef<[u8; 16]>, O: From<[u8; 16]>>(&self, data: I) -> O {
        let encrypted = imp::crypt_block(data.as_ref(), self.as_slice());
        O::from(encrypted)
    }

    pub fn encrypt_mut<T: AsMut<[u8; 16]>>(&self, mut data: T) {
        let encrypted = imp::crypt_block(data.as_mut(), self.as_slice());
        data.as_mut().copy_from_slice(&encrypted);
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DecryptKey {
    expkey: ExpandedKey,
}

impl DecryptKey {
    pub fn decrypt<I: AsRef<[u8; 16]>, O: From<[u8; 16]>>(&self, data: I) -> O {
        let decrypted = imp::crypt_block(data.as_ref(), self.expkey.as_slice());
        O::from(decrypted)
    }

    pub fn decrypt_mut<T: AsMut<[u8; 16]>>(&self, mut data: T) {
        let newblock = imp::crypt_block(data.as_mut(), self.expkey.as_slice());
        data.as_mut().copy_from_slice(&newblock);
    }
}

impl From<ExpandedKey> for DecryptKey {
    fn from(mut expkey: ExpandedKey) -> Self {
        imp::derive_decrypt_key(expkey.as_mut_slice());
        Self { expkey }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::PathBuf,
    };

    use super::*;

    #[test]
    fn basic_key_expand() {
        let key = Key::from([
            0x75, 0x69, 0x49, 0x67, 0x52, 0x55, 0x73, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(key.len, KeyLen::K256);

        let expkey = key.expand();
        let expected = ExpandedKey::K256([
            0x7a03dff8, 0x9e945f05, 0x8608bd45, 0xe87f9980, 0x6cf0f59b, 0x7f587662, 0x26ae8be8,
            0x6cab644b, 0xcbfb3cd5, 0x2611b1a9, 0x57cf9421, 0x1200da0e, 0xe9b8b7d3, 0x8414511e,
            0x25a277f0, 0xd3d2bb5e, 0xed69bfce, 0x3ba9bf7b, 0xc6c8608b, 0xd45e87f9, 0x4503e6e0,
            0x5a45f381, 0x88538be0, 0x4d4a71e5, 0x3b35975f, 0xe24f16f3, 0x1ad473f1, 0xef606f95,
            0xe9b8b97e, 0x47ea299a, 0x2f65b122, 0xd3d2bb5e, 0xc82ca118, 0xcbd57c03, 0x969fccc1,
            0x2c6c8608, 0x7ceac6a2, 0x7c7be84b, 0x79bd5fc0, 0x8a27b7d5, 0x0de90b1c, 0x2b443365,
            0x9d921277, 0x2d59d71e, 0xc9b8b97e, 0xad38bb54, 0x85627edc, 0x39981533, 0xc4db5145,
            0xa742d297, 0x66003daa, 0x5a7f3304, 0xac61540e, 0x4336b2e9, 0x965023c6, 0x82480ba5,
            0xca0cbc48, 0x74d9cff6, 0x294c58f7, 0x8c229ccb, 0x409200ca, 0x2d38bb54, 0x8bcf57f0,
            0xe9661fed, 0x45225246, 0xd07a2213, 0x1fe66003, 0xdaa5a7f3,
        ]);
        assert_eq!(expkey, expected);
    }

    #[test]
    fn basic_key_expand2() {
        let key = Key::from([
            0x71, 0x65, 0x46, 0x66, 0x49, 0x79, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(key.len, KeyLen::K256);
        let expkey = key.expand();
        let deckey: DecryptKey = expkey.into();

        let expected = ExpandedKey::K256([
            0xdaa50a3d, 0x56a0c4b4, 0xef55754d, 0xd2f1130e, 0x7576ac6d, 0x543bd460, 0xecfc7429,
            0xbbc30fe8, 0xb94aceab, 0xb2b2dafe, 0x35c2be25, 0x8e4501f0, 0x81e5d8d3, 0x24c67e11,
            0x34675617, 0x64fb8b2a, 0xf67d4b79, 0x1836ba04, 0xc6d36581, 0xcba21907, 0xf4263a9c,
            0x1d020440, 0x5e755676, 0xaa4e55f1, 0x8774b9b8, 0x81fe00ad, 0x3237fa2b, 0x172283ed,
            0x713d6720, 0x580bde4d, 0xb4ae3364, 0xcff0ab97, 0x5d752e5d, 0xc2347e59, 0xc7a0b3c9,
            0x1462f3a6, 0xd8a7cf64, 0xce4508b0, 0xab73af60, 0xfb452a11, 0x67075b8b, 0x3dd93d72,
            0xeb69c0da, 0xb317be50, 0x66c735db, 0x2f0b8ec6, 0x0fe29300, 0xa6e6d52b, 0x4fa2627d,
            0xef9e0180, 0xa4907272, 0xcc51dab2, 0xb80f5a1b, 0xb18d4bae, 0x52fa7315, 0x67227ebe,
            0x6e3fa650, 0xd755a510, 0x2b3fdd83, 0x6e36715c, 0x943c2c1e, 0xdbeeb0ef, 0xbf935956,
            0x45d938f2, 0x462e822a, 0x73d67954, 0x6c7f66f3, 0x47bd55d5,
        ]);
        assert_eq!(deckey.expkey, expected);
    }

    #[test]
    fn basic_key_derive() {
        let key = Key::from([
            0x75, 0x69, 0x49, 0x67, 0x52, 0x55, 0x73, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(key.len, KeyLen::K256);

        let expkey = key.expand();
        let deckey: DecryptKey = expkey.into();

        let expected_bytes: [u8; 17 * 16] = [
            0x46, 0x52, 0x22, 0x45, 0x13, 0x22, 0x7a, 0xd0, 0x03, 0x60, 0xe6, 0x1f, 0xf3, 0xa7,
            0xa5, 0xda, 0xf2, 0xa7, 0x2c, 0x61, 0x17, 0x03, 0x1f, 0xf1, 0x8a, 0x49, 0x57, 0x77,
            0xb6, 0xbf, 0xdf, 0xab, 0xf4, 0x5f, 0xb1, 0x28, 0xfb, 0x3a, 0x73, 0x26, 0x2a, 0x22,
            0x37, 0xf5, 0xa7, 0x08, 0xe8, 0xbe, 0xd5, 0x52, 0x6a, 0x7a, 0x47, 0xa8, 0xf1, 0x30,
            0x29, 0xa5, 0x06, 0xa9, 0x50, 0x4a, 0x04, 0x7a, 0xca, 0x67, 0xbc, 0x1a, 0xa5, 0x1a,
            0x33, 0x2c, 0x4d, 0x99, 0x4c, 0x69, 0x30, 0xfd, 0xe0, 0x3f, 0x8a, 0x06, 0x38, 0x02,
            0x85, 0x99, 0x51, 0x37, 0x70, 0x6a, 0x02, 0x5d, 0x5c, 0x89, 0x3b, 0x69, 0xc7, 0xa7,
            0x16, 0x85, 0x58, 0x97, 0x97, 0x61, 0x31, 0xba, 0x1e, 0xff, 0x1c, 0x4c, 0x91, 0x7c,
            0x43, 0xbe, 0x6d, 0x62, 0xb4, 0xbe, 0xb4, 0x1a, 0xd3, 0x7c, 0xf8, 0x0c, 0xd8, 0x13,
            0x7c, 0x78, 0xf9, 0xb2, 0x5a, 0x4c, 0x5f, 0x79, 0x22, 0x65, 0x44, 0xe2, 0x26, 0x84,
            0xc1, 0x16, 0x99, 0x80, 0x63, 0xc8, 0x0e, 0x33, 0xe3, 0x1f, 0xb0, 0x52, 0x17, 0xa7,
            0xd8, 0xb1, 0x6c, 0xc6, 0x68, 0x26, 0x0a, 0x39, 0x9f, 0x6a, 0x18, 0x77, 0xd5, 0xf2,
            0x8d, 0x7e, 0x26, 0x99, 0xf3, 0x83, 0x88, 0x8d, 0xd1, 0x69, 0x51, 0xa9, 0x7f, 0xfd,
            0xf5, 0x1a, 0xb2, 0x97, 0x2c, 0xb9, 0x1c, 0x78, 0x9e, 0x69, 0x0d, 0x2b, 0x4e, 0x9d,
            0xdf, 0x0b, 0x4a, 0xc8, 0xaa, 0x06, 0x4a, 0x03, 0x1b, 0x75, 0x1f, 0x85, 0x0d, 0x67,
            0xb7, 0xe8, 0xee, 0x94, 0xdf, 0x7a, 0x34, 0x88, 0x8c, 0x30, 0x93, 0x43, 0xf5, 0xc1,
            0x1c, 0xc5, 0x00, 0x00, 0xfb, 0x17, 0x87, 0x44, 0x61, 0x10, 0x79, 0x25, 0x3d, 0x1d,
            0xc5, 0x23, 0xfa, 0xbd, 0x60, 0xd5, 0x14, 0x19, 0x1e, 0x20, 0xd5, 0x86, 0x52, 0xea,
            0xc4, 0xf2, 0xe5, 0x3b, 0xf8, 0xdf, 0x03, 0x7a, 0x05, 0x5f, 0x94, 0x9e, 0x45, 0xbd,
            0x08, 0x86, 0x80, 0x99, 0x7f, 0xe8,
        ];
        assert_eq!(deckey.expkey.as_bytes(), &expected_bytes);
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn encode_decode_u8() {
        let key = Key::from([
            0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(key.len, KeyLen::K256);

        let raw = Block::from([
            b'e', b'm', b'p', b't', b'y', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        println!("raw: {raw:x?} ({})", std::str::from_utf8(&raw.0).unwrap());

        let expkey = key.expand();
        println!("expkey: {:x?}", expkey.as_bytes());
        let encoded: Block = expkey.encrypt(&raw);
        println!("encoded: {:x?}", encoded);
        assert_eq!(
            encoded.0,
            [
                0x26, 0x86, 0x31, 0xe0, 0xa3, 0x39, 0x88, 0xdc, 0xf7, 0x7f, 0x91, 0xf5, 0x23, 0x57,
                0x7f, 0x63
            ]
        );

        let deckey = DecryptKey::from(expkey);
        println!("deckey: {:x?}", deckey.expkey.as_bytes());
        let expected_bytes: [u8; 17 * 16] = [
            0x72, 0x56, 0x81, 0x98, 0x50, 0x62, 0x4c, 0xe6, 0x60, 0x1b, 0xac, 0x4c, 0x47, 0x6f,
            0xc1, 0xa0, 0x3b, 0x63, 0xf3, 0xa9, 0xd7, 0x53, 0x1a, 0xa5, 0x85, 0x9c, 0xec, 0x0e,
            0x6d, 0x98, 0x7f, 0x1d, 0x3f, 0xdd, 0x6e, 0xa9, 0x63, 0xe3, 0x86, 0xe0, 0x82, 0xd9,
            0x5f, 0xe9, 0xab, 0x55, 0x16, 0xd2, 0x32, 0x10, 0x6b, 0x02, 0xf1, 0x3e, 0x89, 0xc4,
            0x96, 0xf6, 0xba, 0x3d, 0x93, 0xe1, 0x19, 0xf4, 0x16, 0x5a, 0x5f, 0x2b, 0x59, 0xce,
            0xef, 0x45, 0x8f, 0xc6, 0x30, 0x08, 0xff, 0x57, 0x90, 0x3b, 0xab, 0xd3, 0xe3, 0xb9,
            0x77, 0xf3, 0x9a, 0xa5, 0xa9, 0x90, 0x60, 0x82, 0x51, 0xa4, 0xe3, 0x01, 0x3d, 0xa3,
            0x34, 0x0d, 0xdf, 0x10, 0x95, 0x43, 0xc3, 0x82, 0xe2, 0x45, 0x33, 0xd0, 0x93, 0x3c,
            0x4c, 0xee, 0x56, 0x8e, 0x45, 0x06, 0xc4, 0xd1, 0xab, 0x20, 0xb9, 0x97, 0x75, 0xcb,
            0xc2, 0xcc, 0x51, 0x3b, 0x6e, 0x4b, 0x63, 0x6d, 0x1f, 0xcd, 0xb7, 0xdd, 0x7e, 0x54,
            0x12, 0x4f, 0x41, 0x12, 0x8b, 0xd3, 0xc3, 0x99, 0x95, 0x11, 0x58, 0x67, 0x47, 0x5e,
            0xae, 0x4c, 0x5d, 0xa8, 0xcf, 0x2d, 0x04, 0x3d, 0xb7, 0x58, 0xf6, 0x33, 0x05, 0x5f,
            0x82, 0x57, 0xf5, 0xb0, 0xea, 0x7d, 0x2e, 0x74, 0x23, 0xa4, 0xbe, 0x48, 0xb1, 0x52,
            0x88, 0xea, 0x76, 0xf6, 0x8d, 0x41, 0xc5, 0x2d, 0x57, 0x90, 0x7b, 0x5d, 0x42, 0xa2,
            0x3d, 0x9e, 0x8f, 0x20, 0xec, 0xdd, 0x29, 0xfb, 0xbd, 0xe0, 0x90, 0x39, 0xab, 0xf3,
            0xcf, 0xb5, 0x7b, 0xff, 0x96, 0xa9, 0x89, 0x90, 0x6c, 0xae, 0x5d, 0xa8, 0xef, 0x0d,
            0x4f, 0x7f, 0xb5, 0x82, 0x18, 0x77, 0x2f, 0x5d, 0x04, 0x6d, 0x39, 0xcf, 0x48, 0xfe,
            0xde, 0xf9, 0xb9, 0x7e, 0x74, 0x17, 0x34, 0xad, 0x2b, 0x89, 0x90, 0x30, 0x9b, 0xad,
            0x23, 0x33, 0x77, 0x57, 0xdc, 0x64, 0xe2, 0xe3, 0xbd, 0xe1, 0x86, 0x7e, 0x0c, 0xb4,
            0x1c, 0x4e, 0x6d, 0xb0, 0x32, 0xc5,
        ];
        assert_eq!(deckey.expkey.as_bytes(), &expected_bytes);

        let decoded: Block = deckey.decrypt(encoded);
        println!(
            "decoded: {:x?} ({})",
            decoded,
            std::str::from_utf8(&decoded.0).unwrap()
        );

        assert_eq!(decoded, raw);
    }

    fn parse_kat_vectors(path: &str) {
        let file = File::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap();
        let reader = BufReader::new(file);

        let mut key: Option<Key> = None;
        let mut pt: Option<Vec<u8>> = None;
        let mut ct: Option<Vec<u8>> = None;

        for line in reader.lines() {
            let line = line.unwrap();
            let mut parts = line.split_ascii_whitespace();
            if let (Some(id), Some(equal), Some(value)) = (parts.next(), parts.next(), parts.next())
            {
                if equal != "=" {
                    panic!("Malformed syntax. Expected either `KEY = VAL` or empty line");
                }

                let bytes = decode_hex(value);
                match id {
                    "KEY" => {
                        let newkey = Key::try_from(bytes.as_slice()).unwrap();
                        let prev = key.replace(newkey);
                        assert!(prev.is_none());
                    }
                    "PT" => {
                        let prev = pt.replace(bytes);
                        assert!(prev.is_none());
                    }
                    "CT" => {
                        let prev = ct.replace(bytes);
                        assert!(prev.is_none());
                    }
                    _ => panic!("unknown ID ({id}) in `ID = VAL` line"),
                }
            } else {
                let key = key.take().unwrap();
                let pt = pt.take().unwrap();
                let ct = ct.take().unwrap();
                println!("k={key:x?} pt={pt:x?} ct={ct:x?}");

                let pt_blocks: Vec<Block> = pt.chunks(16).map(Block::new).collect();
                let ct_blocks: Vec<Block> = ct.chunks(16).map(Block::new).collect();

                let enckey = key.expand();
                let deckey = DecryptKey::from(enckey.clone());

                let pt_blocks_crypted: Vec<Block> =
                    pt_blocks.iter().map(|b| enckey.encrypt(b)).collect();
                let ct_blocks_decrypted: Vec<Block> =
                    ct_blocks.iter().map(|b| deckey.decrypt(b)).collect();

                assert_eq!(pt_blocks_crypted, ct_blocks);
                assert_eq!(ct_blocks_decrypted, pt_blocks);
            }
        }
    }

    #[test]
    fn encode_decode_vectors_kat256() {
        parse_kat_vectors("resources/ECB/ARIA256(ECB)KAT.txt");
    }

    #[test]
    fn encode_decode_vectors_kat192() {
        parse_kat_vectors("resources/ECB/ARIA192(ECB)KAT.txt");
    }

    #[test]
    fn encode_decode_vectors_kat128() {
        parse_kat_vectors("resources/ECB/ARIA128(ECB)KAT.txt");
    }

    #[test]
    fn encode_decode_vectors_mmt256() {
        parse_kat_vectors("resources/ECB/ARIA256(ECB)MMT.txt");
    }

    #[test]
    fn encode_decode_vectors_mmt192() {
        parse_kat_vectors("resources/ECB/ARIA192(ECB)MMT.txt");
    }

    #[test]
    fn encode_decode_vectors_mmt128() {
        parse_kat_vectors("resources/ECB/ARIA128(ECB)MMT.txt");
    }
}
