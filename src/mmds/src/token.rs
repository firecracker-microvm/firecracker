// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Temporarily disable unused warnings.
// TODO: remove these once the Token integration is completed.
#![allow(dead_code)]

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::ops::Add;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, io};

/// Length of the key used for encryption.
pub const KEY_LEN: usize = 32;
/// Length of encryption payload.
pub const PAYLOAD_LEN: usize = std::mem::size_of::<u64>();
/// Length of encryption tag.
pub const TAG_LEN: usize = 16;
/// Length of initialization vector.
pub const IV_LEN: usize = 12;
/// Path to token.
pub const PATH_TO_TOKEN: &str = "/latest/api/token";
/// Minimum lifetime of token.
pub const MIN_TOKEN_TTL_SECONDS: u32 = 1;
/// Maximum lifetime of token.
pub const MAX_TOKEN_TTL_SECONDS: u32 = 21600;
/// Randomness pool file path.
const RANDOMNESS_POOL: &str = "/dev/urandom";

#[derive(Debug)]
pub enum Error {
    /// Failed to extract expiry from token sequence.
    ExpiryExtraction,
    /// Time to live value for token is invalid.
    InvalidTtlValue(u32),
    /// Failed to create token authority entity.
    TokenAuthorityCreation(io::Error),
    /// Failed to generate token.
    TokenGeneration,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            Error::ExpiryExtraction => write!(f, "Failed to extract expiry value from token."),
            Error::InvalidTtlValue(value) => write!(
                f,
                "Invalid time to live value provided for token: {}. \
                Please provide a value between {} and {}.",
                value, MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS,
            ),
            Error::TokenAuthorityCreation(err) => {
                write!(f, "Failed to create token authority: {}.", err)
            }
            Error::TokenGeneration => write!(f, "Failed to generate token."),
        }
    }
}

#[derive(Clone)]
pub struct TokenAuthority {
    cipher: aes_gcm::Aes256Gcm,
}

impl TokenAuthority {
    /// Create a new token authority entity.
    pub fn new() -> Result<TokenAuthority, Error> {
        // Randomly generate a 256-bit key to be used for encryption/decryption purposes.
        let mut key = [0u8; KEY_LEN];
        read_into_buf_from_entropy_pool(&mut key).map_err(Error::TokenAuthorityCreation)?;

        // Create cipher entity to handle encryption/decryption.
        let cipher = Aes256Gcm::new(Key::from_slice(&key));

        Ok(TokenAuthority { cipher })
    }

    /// Generate encoded token string using the token time to live provided.
    pub fn generate_token_secret(&self, ttl_seconds: u32) -> Result<String, Error> {
        // Create token structure containing the encrypted expiry value.
        let token_struct = self.create_token_struct(ttl_seconds)?;
        // Encode struct into base64 in order to obtain token string.
        TokenAuthority::base64_encode_token_struct(&token_struct)
    }

    /// Create a new Token structure to encrypt.
    fn create_token_struct(&self, ttl_seconds: u32) -> Result<Token, Error> {
        // Validate token time to live against bounds.
        if !TokenAuthority::check_ttl(ttl_seconds) {
            return Err(Error::InvalidTtlValue(ttl_seconds));
        }

        // Generate 12-byte random nonce.
        let mut iv = [0u8; IV_LEN];
        read_into_buf_from_entropy_pool(&mut iv).map_err(|_| Error::TokenGeneration)?;

        // Compute expiration time from ttl.
        let expiry = TokenAuthority::compute_expiry(ttl_seconds);
        // Encrypt expiry using the nonce.
        let (payload, tag) = self.encrypt_expiry(expiry, iv.as_ref())?;

        Ok(Token::new(iv, payload, tag))
    }

    /// Encrypt expiry using AES-GCM block cipher and return payload and tag obtained.
    fn encrypt_expiry(
        &self,
        expiry: u64,
        iv: &[u8],
    ) -> Result<([u8; PAYLOAD_LEN], [u8; TAG_LEN]), Error> {
        // Create Nonce object from initialization vector.
        let nonce = Nonce::from_slice(iv);
        // Convert expiry u64 value into bytes.
        let mut expiry_as_bytes: Vec<u8> =
            bincode::serialize(&expiry).map_err(|_| Error::TokenGeneration)?;

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, b"", &mut expiry_as_bytes)
            .map_err(|_| Error::TokenGeneration)?;

        // Payload must be of size `PAYLOAD_LEN`.
        let payload: [u8; PAYLOAD_LEN] = expiry_as_bytes
            .try_into()
            .map_err(|_| Error::TokenGeneration)?;
        // Tag must be of size `TAG_LEN`.
        let tag_bytes: [u8; TAG_LEN] = tag
            .as_slice()
            .try_into()
            .map_err(|_| Error::TokenGeneration)?;

        Ok((payload, tag_bytes))
    }

    /// Encode token structure into a string using base64 encoding.
    fn base64_encode_token_struct(token: &Token) -> Result<String, Error> {
        let token_bytes: Vec<u8> = bincode::serialize(token).map_err(|_| Error::TokenGeneration)?;
        let mut encoded_token = Vec::new();
        // Ensure vector has enough space for base64 encoding.
        encoded_token.resize(get_size_of_base64_encoding(token_bytes.len()), 0);
        // Encode token structure bytes into base64.
        let size = base64::encode_config_slice(token_bytes, base64::STANDARD, &mut encoded_token);
        encoded_token.resize(size, 0);

        // Convert base64 bytes to String.
        // Safe to unwrap because `encoded_token` represents a base64 encoding.
        Ok(String::from_utf8(encoded_token).unwrap())
    }

    /// Attempts to decrypt expiry value within token sequence. Returns false if expiry
    /// cannot be decrypted. If decryption succeeds, returns true if token has not expired
    /// (i.e. current time is greater than expiry) and false otherwise.
    pub fn is_valid(&self, token: &str) -> bool {
        let mut ciphertext = Vec::new();

        // Decode token struct from base64.
        let token_struct = match TokenAuthority::base64_decode_token_struct(token) {
            Ok(token_struct) => token_struct,
            Err(_) => return false,
        };

        // Validate constant fields inside decoded token structure.
        if !token_struct.sanity_check() {
            return false;
        }

        // Construct ciphertext from payload and tag within token structure.
        ciphertext.extend_from_slice(&token_struct.payload);
        ciphertext.extend_from_slice(&token_struct.tag);

        // Decrypt ttl using AES-GCM block cipher.
        let expiry = match self.decrypt_expiry(&ciphertext, &token_struct.iv) {
            Ok(expiry) => expiry,
            Err(_) => return false,
        };

        // Get current time.
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH.");
        let time_now_as_seconds = time_now.as_secs();

        expiry > time_now_as_seconds
    }

    /// Decrypt ciphertext composed of payload and tag to obtain the expiry value.
    fn decrypt_expiry(&self, ciphertext: &[u8], iv: &[u8]) -> Result<u64, Error> {
        // Create Nonce object from initialization vector.
        let nonce = Nonce::from_slice(iv);
        // Decrypt expiry as vector of bytes from ciphertext.
        let expiry_as_bytes = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::ExpiryExtraction)?;
        // Get expiry value in seconds from bytes.
        let expiry: u64 =
            bincode::deserialize(&expiry_as_bytes).map_err(|_| Error::ExpiryExtraction)?;

        Ok(expiry)
    }

    /// Decode token structure from base64 string.
    fn base64_decode_token_struct(encoded_token: &str) -> Result<Token, Error> {
        let mut token_bytes = vec![0; encoded_token.len()];
        let size = base64::decode_config_slice(
            encoded_token.as_bytes(),
            base64::STANDARD,
            &mut token_bytes,
        )
        .map_err(|_| Error::ExpiryExtraction)?;
        // Resize to actual length because base64 encodings require more space.
        token_bytes.resize(size, 0);

        let token: Token =
            bincode::deserialize(&token_bytes).map_err(|_| Error::ExpiryExtraction)?;
        Ok(token)
    }

    /// Validate the token time to live against bounds.
    fn check_ttl(ttl_seconds: u32) -> bool {
        (MIN_TOKEN_TTL_SECONDS..=MAX_TOKEN_TTL_SECONDS).contains(&ttl_seconds)
    }

    /// Compute expiry time in seconds by adding the time to live provided
    /// to the current time measured in seconds.
    fn compute_expiry(ttl_seconds: u32) -> u64 {
        // Get time elapsed since UNIX_EPOCH.
        let now_as_duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH.");
        // Convert elapsed time into seconds.
        let ttl_duration = Duration::from_secs(u64::from(ttl_seconds));

        // Compute expiry by adding ttl value to current time in seconds.
        // This addition is safe because ttl is verified beforehand and
        // can never be more than 6h.
        let expiry_duration = now_as_duration.add(ttl_duration);

        expiry_duration.as_secs()
    }
}

/// Structure for token information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct Token {
    version: u16,
    payload_size: u16,
    // Nonce or Initialization Vector.
    iv: [u8; IV_LEN],
    // Encrypted expire time.
    payload: [u8; PAYLOAD_LEN],
    // Tag returned after encryption.
    tag: [u8; TAG_LEN],
}

impl Token {
    /// Create a new token struct.
    fn new(iv: [u8; IV_LEN], payload: [u8; PAYLOAD_LEN], tag: [u8; TAG_LEN]) -> Self {
        Token {
            version: 1,
            payload_size: PAYLOAD_LEN as u16,
            iv,
            payload,
            tag,
        }
    }

    /// Validate constant fields inside the token structure.
    fn sanity_check(&self) -> bool {
        self.version == 1 && self.payload_size == PAYLOAD_LEN as u16
    }
}

// Base64 encodings require more space than the number of bytes to encode.
// This ensures enough space for encoding and padding.
fn get_size_of_base64_encoding(bytes_size: usize) -> usize {
    bytes_size * 4 / 3 + 4
}

fn read_into_buf_from_entropy_pool(buf: &mut [u8]) -> Result<(), io::Error> {
    let mut random_file = File::open(Path::new(RANDOMNESS_POOL))?;
    random_file.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_read_into_buf_from_entropy_pool() {
        let mut buf = [0u8; 12];
        read_into_buf_from_entropy_pool(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 12]);
    }

    #[test]
    fn test_token_struct_validate() {
        let mut token = Token::new([0u8; IV_LEN], [0u8; PAYLOAD_LEN], [0u8; TAG_LEN]);
        assert!(token.sanity_check());

        // Test invalid version.
        {
            token.version = 2;
            assert!(!token.sanity_check());
        }

        // Test invalid payload size.
        {
            token.payload_size = 0;
            assert!(!token.sanity_check());
        }
    }

    #[test]
    fn test_check_tll() {
        // Test invalid time to live values.
        assert!(!TokenAuthority::check_ttl(MIN_TOKEN_TTL_SECONDS - 1));
        assert!(!TokenAuthority::check_ttl(MAX_TOKEN_TTL_SECONDS + 1));

        // Test time to live value within bounds.
        assert!(TokenAuthority::check_ttl(MIN_TOKEN_TTL_SECONDS));
        assert!(TokenAuthority::check_ttl(MAX_TOKEN_TTL_SECONDS / 2));
        assert!(TokenAuthority::check_ttl(MAX_TOKEN_TTL_SECONDS));
    }

    #[test]
    fn test_create_token_struct() {
        let token_authority = TokenAuthority::new().unwrap();

        // Test invalid time to live value.
        assert_eq!(
            token_authority
                .create_token_struct(0)
                .unwrap_err()
                .to_string(),
            format!(
                "Invalid time to live value provided for token: 0. \
                Please provide a value between {} and {}.",
                MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS
            )
        );

        // Test valid time to live value.
        let token_struct = token_authority.create_token_struct(1).unwrap();
        assert_eq!(token_struct.version, 1);
        assert_eq!(token_struct.iv.len(), IV_LEN);
        assert_eq!(token_struct.payload_size, PAYLOAD_LEN as u16);
        assert_eq!(token_struct.payload.len(), PAYLOAD_LEN);
        assert_eq!(token_struct.tag.len(), TAG_LEN);
    }

    #[test]
    fn test_compute_expiry() {
        let time_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let expiry = TokenAuthority::compute_expiry(1);
        assert_eq!(expiry - time_now.as_secs(), 1);

        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = TokenAuthority::compute_expiry(0);
        assert_eq!(expiry, time_now);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let token_authority = TokenAuthority::new().unwrap();
        let mut iv = [0u8; IV_LEN];
        read_into_buf_from_entropy_pool(&mut iv).unwrap();
        let expiry = TokenAuthority::compute_expiry(10);

        // Test valid ciphertext.
        let (payload, mut tag) = token_authority.encrypt_expiry(expiry, &iv).unwrap();
        let mut ciphertext = vec![];
        ciphertext.extend_from_slice(&payload);
        ciphertext.extend_from_slice(&tag);
        let decrypted_expiry = token_authority
            .decrypt_expiry(&ciphertext, iv.as_mut())
            .unwrap();
        assert_eq!(expiry, decrypted_expiry);

        // Test ciphertext with corrupted payload.
        ciphertext[0] += 1;
        assert!(token_authority
            .decrypt_expiry(&ciphertext, iv.as_mut())
            .is_err());

        // Test ciphertext with corrupted tag.
        tag[0] += 1;
        let mut ciphertext = vec![];
        ciphertext.extend_from_slice(&payload);
        ciphertext.extend_from_slice(&tag);
        assert!(token_authority
            .decrypt_expiry(&ciphertext, iv.as_mut())
            .is_err());
    }

    #[test]
    fn test_encode_decode() {
        let token_struct = Token::new([0u8; IV_LEN], [0u8; PAYLOAD_LEN], [0u8; TAG_LEN]);
        let mut token = TokenAuthority::base64_encode_token_struct(&token_struct).unwrap();
        let decoded_token_struct = TokenAuthority::base64_decode_token_struct(&token).unwrap();
        assert_eq!(token_struct, decoded_token_struct);

        // Decode invalid base64 bytes sequence.
        token.push('x');
        assert!(TokenAuthority::base64_decode_token_struct(&token).is_err());
    }

    #[test]
    fn test_token_authority() {
        let token_authority = TokenAuthority::new().unwrap();

        // Test time to live value too small.
        assert_eq!(
            token_authority
                .generate_token_secret(MIN_TOKEN_TTL_SECONDS - 1)
                .unwrap_err()
                .to_string(),
            format!(
                "Invalid time to live value provided for token: {}. \
                Please provide a value between {} and {}.",
                MIN_TOKEN_TTL_SECONDS - 1,
                MIN_TOKEN_TTL_SECONDS,
                MAX_TOKEN_TTL_SECONDS
            )
        );

        // Test time to live value too big.
        assert_eq!(
            token_authority
                .generate_token_secret(MAX_TOKEN_TTL_SECONDS + 1)
                .unwrap_err()
                .to_string(),
            format!(
                "Invalid time to live value provided for token: {}. \
                Please provide a value between {} and {}.",
                MAX_TOKEN_TTL_SECONDS + 1,
                MIN_TOKEN_TTL_SECONDS,
                MAX_TOKEN_TTL_SECONDS
            )
        );

        // Generate token with lifespan of 60 seconds.
        let token0 = token_authority.generate_token_secret(60).unwrap();
        assert!(token_authority.is_valid(&token0));

        // Generate token with lifespan of one second.
        let token1 = token_authority.generate_token_secret(1).unwrap();
        assert!(token_authority.is_valid(&token1));
        // Wait for `token1` to expire.
        sleep(Duration::new(1, 0));
        assert!(!token_authority.is_valid(&token1));
        // The first token should still be valid.
        assert!(token_authority.is_valid(&token0));
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::ExpiryExtraction.to_string(),
            "Failed to extract expiry value from token."
        );

        assert_eq!(
            Error::InvalidTtlValue(0).to_string(),
            format!(
                "Invalid time to live value provided for token: 0. \
                Please provide a value between {} and {}.",
                MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS
            )
        );

        assert_eq!(
            Error::TokenAuthorityCreation(io::Error::from_raw_os_error(0)).to_string(),
            format!(
                "Failed to create token authority: {}.",
                io::Error::from_raw_os_error(0)
            )
        );

        assert_eq!(
            Error::TokenGeneration.to_string(),
            "Failed to generate token."
        );
    }
}
