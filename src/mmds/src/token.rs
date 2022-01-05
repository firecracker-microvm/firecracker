// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aead::NewAead;
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, Nonce};
use bincode::{DefaultOptions, Error as BincodeError, Options};
use logger::warn;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::ops::Add;
use std::path::Path;
use std::{fmt, io};
use utils::time::{get_time_s, ClockType};

/// Length of initialization vector.
pub const IV_LEN: usize = 12;
/// Length of the key used for encryption.
pub const KEY_LEN: usize = 32;
/// Length of encryption payload.
pub const PAYLOAD_LEN: usize = std::mem::size_of::<u64>();
/// Length of encryption tag.
pub const TAG_LEN: usize = 16;

/// Minimum lifetime of token.
pub const MIN_TOKEN_TTL_SECONDS: u32 = 1;
/// Maximum lifetime of token.
pub const MAX_TOKEN_TTL_SECONDS: u32 = 21600;

/// Path to token.
pub const PATH_TO_TOKEN: &str = "/latest/api/token";
/// Randomness pool file path.
const RANDOMNESS_POOL: &str = "/dev/urandom";

/// Token length limit to ensure we don't bother decrypting huge character
/// sequences. Tokens larger than this are automatically rejected. The value
/// is computed based on the expected length of the base64 encoded Token struct
/// including a small deviation.
const TOKEN_LENGTH_LIMIT: usize = 70;
/// Byte limit passed to `bincode` to guard against allocating
/// too much memory when deserializing tokens.
const DESERIALIZATION_BYTES_LIMIT: usize = std::mem::size_of::<Token>();

#[derive(Debug)]
pub enum Error {
    /// Failed to extract entropy from pool.
    EntropyPool(io::Error),
    /// Failed to extract expiry from token sequence.
    ExpiryExtraction,
    /// Token authority has invalid state.
    InvalidState,
    /// Time to live value for token is invalid.
    InvalidTtlValue(u32),
    /// Token serialization failed.
    Serialization(BincodeError),
    /// Failed to encrypt token.
    TokenEncryption,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            Error::EntropyPool(err) => {
                write!(
                    f,
                    "Failed to extract entropy from /dev/urandom entropy pool: {}.",
                    err
                )
            }
            Error::ExpiryExtraction => write!(f, "Failed to extract expiry value from token."),
            Error::InvalidState => write!(f, "Invalid token authority state."),
            Error::InvalidTtlValue(value) => write!(
                f,
                "Invalid time to live value provided for token: {}. \
                Please provide a value between {} and {}.",
                value, MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS,
            ),
            Error::Serialization(err) => write!(f, "Bincode serialization failed: {}.", err),
            Error::TokenEncryption => write!(f, "Failed to encrypt token."),
        }
    }
}

pub struct TokenAuthority {
    cipher: aes_gcm::Aes256Gcm,
    // Number of tokens encrypted under the current key.
    num_encrypted_tokens: u32,
    // Source of entropy.
    entropy_pool: File,
    // Additional Authentication Data used for encryption and decryption.
    aad: String,
}

impl TokenAuthority {
    /// Create a new token authority entity.
    pub fn new() -> Result<TokenAuthority, Error> {
        let mut file = File::open(Path::new(RANDOMNESS_POOL)).map_err(Error::EntropyPool)?;

        Ok(TokenAuthority {
            cipher: TokenAuthority::create_cipher(&mut file)?,
            num_encrypted_tokens: 0,
            entropy_pool: file,
            aad: "".to_string(),
        })
    }

    /// Set Additional Authenticated Data to be used for
    /// encryption and decryption of the session token.
    pub fn set_aad(&mut self, instance_id: &str) {
        self.aad = format!("microvmid={}", instance_id);
    }

    /// Generate encoded token string using the token time to live provided.
    pub fn generate_token_secret(&mut self, ttl_seconds: u32) -> Result<String, Error> {
        // Check number of tokens encrypted under the current key. We need to
        // make sure no more than 2^32 tokens are encrypted with the same key.
        // If this number is reached, we need to reinitialize the cipher entity.
        self.check_encryption_count()?;
        // Create token structure containing the encrypted expiry value.
        let token = self.create_token(ttl_seconds)?;
        // Encode struct into base64 in order to obtain token string.
        let encoded_token = token.base64_encode()?;
        // Increase the count of encrypted tokens.
        self.num_encrypted_tokens += 1;

        Ok(encoded_token)
    }

    /// Create a new Token structure to encrypt.
    fn create_token(&mut self, ttl_seconds: u32) -> Result<Token, Error> {
        // Validate token time to live against bounds.
        if !TokenAuthority::check_ttl(ttl_seconds) {
            return Err(Error::InvalidTtlValue(ttl_seconds));
        }

        // Generate 12-byte random nonce.
        let mut iv = [0u8; IV_LEN];
        self.entropy_pool
            .read_exact(&mut iv)
            .map_err(Error::EntropyPool)?;

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
        let mut expiry_as_bytes = expiry.to_le_bytes();

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, self.aad.as_bytes(), &mut expiry_as_bytes)
            .map_err(|_| Error::TokenEncryption)?;

        // Tag must be of size `TAG_LEN`.
        let tag_as_bytes: [u8; TAG_LEN] = tag
            .as_slice()
            .try_into()
            .map_err(|_| Error::TokenEncryption)?;

        Ok((expiry_as_bytes, tag_as_bytes))
    }

    /// Attempts to decrypt expiry value within token sequence. Returns false if expiry
    /// cannot be decrypted. If decryption succeeds, returns true if token has not expired
    /// (i.e. current time is greater than expiry) and false otherwise.
    pub fn is_valid(&self, encoded_token: &str) -> bool {
        // Check size of encoded token struct.
        if encoded_token.len() > TOKEN_LENGTH_LIMIT {
            return false;
        }

        // Decode token struct from base64.
        let mut token = match Token::base64_decode(encoded_token) {
            Ok(token) => token,
            Err(_) => return false,
        };

        // Decrypt ttl using AES-GCM block cipher.
        let expiry = match self.decrypt_expiry(&mut token.payload, &token.tag, &token.iv) {
            Ok(expiry) => expiry,
            Err(_) => return false,
        };

        // Compare expiry with current time in seconds.
        expiry > get_time_s(ClockType::Monotonic)
    }

    /// Decrypt ciphertext composed of payload and tag to obtain the expiry value.
    fn decrypt_expiry(
        &self,
        payload: &mut [u8; PAYLOAD_LEN],
        tag: &[u8],
        iv: &[u8],
    ) -> Result<u64, Error> {
        // Create Nonce object from initialization vector.
        let nonce = Nonce::from_slice(iv);
        // Decrypt expiry as vector of bytes from ciphertext.
        self.cipher
            .decrypt_in_place_detached(
                nonce,
                self.aad.as_bytes(),
                payload,
                aes_gcm::Tag::from_slice(tag),
            )
            .map_err(|_| Error::ExpiryExtraction)?;
        let expiry_as_bytes = payload[..]
            .try_into()
            .map_err(|_| Error::ExpiryExtraction)?;

        // Return expiry value in seconds.
        Ok(u64::from_le_bytes(expiry_as_bytes))
    }

    /// Create a new AES-GCM cipher entity.
    fn create_cipher(entropy_pool: &mut File) -> Result<Aes256Gcm, Error> {
        // Randomly generate a 256-bit key to be used for encryption/decryption purposes.
        let mut key = [0u8; KEY_LEN];
        entropy_pool
            .read_exact(&mut key)
            .map_err(Error::EntropyPool)?;

        // Create cipher entity to handle encryption/decryption.
        Ok(Aes256Gcm::new(Key::from_slice(&key)))
    }

    /// Make sure to reinitialize the cipher under a new key before reaching
    /// a count of 2^32 encrypted tokens under the same cipher entity.
    fn check_encryption_count(&mut self) -> Result<(), Error> {
        // Make sure no more than 2^32 - 1 tokens are encrypted under
        // the same encryption key.
        if self.num_encrypted_tokens == u32::MAX {
            // Reinitialize the cipher entity under a new key when limit is exceeded.
            // As a result, all valid tokens created under the previous key are invalidated.
            // By design, we don't retain the cipher used to encrypt previous tokens,
            // because reaching the limit is very unlikely and should not happen under
            // healthy interactions with MMDS. However, if it happens, we expect the
            // customer code to have a retry mechanism in place and regenerate the
            // session token if the previous ones become invalid.
            self.cipher = TokenAuthority::create_cipher(&mut self.entropy_pool)?;
            // Reset encrypted tokens count.
            self.num_encrypted_tokens = 0;
            warn!(
                "The limit of tokens generated under current MMDS token authority
                has been reached. MMDS's token authority entity has been reseeded
                and all previously created tokens are now invalid."
            );
        }

        Ok(())
    }

    /// Validate the token time to live against bounds.
    fn check_ttl(ttl_seconds: u32) -> bool {
        MIN_TOKEN_TTL_SECONDS <= ttl_seconds && ttl_seconds <= MAX_TOKEN_TTL_SECONDS
    }

    /// Compute expiry time in seconds by adding the time to live provided
    /// to the current time measured in seconds.
    fn compute_expiry(ttl_as_seconds: u32) -> u64 {
        // Get current time in seconds.
        let now_as_seconds = get_time_s(ClockType::Monotonic);

        // Compute expiry by adding ttl value to current time in seconds.
        // This addition is safe because ttl is verified beforehand and
        // can never be more than 6h.
        now_as_seconds.add(ttl_as_seconds as u64)
    }
}

/// Structure for token information.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Token {
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
        Token { iv, payload, tag }
    }

    /// Encode token structure into a string using base64 encoding.
    fn base64_encode(&self) -> Result<String, Error> {
        let token_bytes: Vec<u8> = bincode::serialize(self).map_err(Error::Serialization)?;

        // Encode token structure bytes into base64.
        Ok(base64::encode_config(token_bytes, base64::STANDARD))
    }

    /// Decode token structure from base64 string.
    fn base64_decode(encoded_token: &str) -> Result<Self, Error> {
        let token_bytes = base64::decode_config(encoded_token, base64::STANDARD)
            .map_err(|_| Error::ExpiryExtraction)?;

        let token: Token = DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(DESERIALIZATION_BYTES_LIMIT as u64)
            .deserialize(&token_bytes)
            .map_err(|_| Error::ExpiryExtraction)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

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
    fn test_set_aad() {
        let mut token_authority = TokenAuthority::new().unwrap();
        assert_eq!(token_authority.aad, "".to_string());

        token_authority.set_aad("foo");
        assert_eq!(token_authority.aad, "microvmid=foo".to_string());
    }

    #[test]
    fn test_create_token() {
        let mut token_authority = TokenAuthority::new().unwrap();

        // Test invalid time to live value.
        assert_eq!(
            token_authority.create_token(0).unwrap_err().to_string(),
            format!(
                "Invalid time to live value provided for token: 0. \
                Please provide a value between {} and {}.",
                MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS
            )
        );

        // Test valid time to live value.
        let token = token_authority.create_token(1).unwrap();
        assert_eq!(token.iv.len(), IV_LEN);
        assert_eq!(token.payload.len(), PAYLOAD_LEN);
        assert_eq!(token.tag.len(), TAG_LEN);
    }

    #[test]
    fn test_compute_expiry() {
        let time_now = get_time_s(ClockType::Monotonic);
        let expiry = TokenAuthority::compute_expiry(1);
        assert_eq!(expiry - time_now, 1);

        let time_now = get_time_s(ClockType::Monotonic);
        let expiry = TokenAuthority::compute_expiry(0);
        assert_eq!(expiry, time_now);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut token_authority = TokenAuthority::new().unwrap();
        let mut file = File::open(Path::new(RANDOMNESS_POOL)).unwrap();
        let mut iv = [0u8; IV_LEN];
        file.read_exact(&mut iv).unwrap();
        let expiry = TokenAuthority::compute_expiry(10);

        // Test valid ciphertext.
        let (mut payload, mut tag) = token_authority.encrypt_expiry(expiry, &iv).unwrap();
        let decrypted_expiry = token_authority
            .decrypt_expiry(&mut payload, &tag, iv.as_mut())
            .unwrap();
        assert_eq!(expiry, decrypted_expiry);

        // Test decrypting expiry under a different AAD than it was encrypted with.
        token_authority.set_aad("foo");
        assert_eq!(
            token_authority
                .decrypt_expiry(&mut payload, &tag, iv.as_mut())
                .unwrap_err()
                .to_string(),
            Error::ExpiryExtraction.to_string()
        );

        // Test ciphertext with corrupted payload.
        payload[0] += 1;
        assert_eq!(
            token_authority
                .decrypt_expiry(&mut payload, &tag, iv.as_mut())
                .unwrap_err()
                .to_string(),
            Error::ExpiryExtraction.to_string()
        );

        // Test ciphertext with corrupted tag.
        tag[0] += 1;
        let mut ciphertext = vec![];
        ciphertext.extend_from_slice(&payload);
        ciphertext.extend_from_slice(&tag);
        assert_eq!(
            token_authority
                .decrypt_expiry(&mut payload, &tag, iv.as_mut())
                .unwrap_err()
                .to_string(),
            Error::ExpiryExtraction.to_string()
        );
    }

    #[test]
    fn test_encode_decode() {
        let expected_token = Token::new([0u8; IV_LEN], [0u8; PAYLOAD_LEN], [0u8; TAG_LEN]);
        let mut encoded_token = expected_token.base64_encode().unwrap();
        let actual_token = Token::base64_decode(&encoded_token).unwrap();
        assert_eq!(actual_token, expected_token);

        // Decode invalid base64 bytes sequence.
        encoded_token.push('x');
        assert!(Token::base64_decode(&encoded_token).is_err());
    }

    #[test]
    fn test_generate_token_secret() {
        let mut token_authority = TokenAuthority::new().unwrap();

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
        let _ = token_authority.generate_token_secret(60).unwrap();
        assert_eq!(token_authority.num_encrypted_tokens, 1);
    }

    #[test]
    fn test_is_valid() {
        let mut token_authority = TokenAuthority::new().unwrap();

        // Test token with size bigger than expected.
        assert!(!token_authority.is_valid(str::repeat("a", TOKEN_LENGTH_LIMIT + 1).as_str()));

        // Test valid token.
        let token0 = token_authority.generate_token_secret(1).unwrap();
        assert!(token_authority.is_valid(&token0));
    }

    #[test]
    fn test_token_authority() {
        let mut token_authority = TokenAuthority::new().unwrap();

        // Generate token with lifespan of 60 seconds.
        let token0 = token_authority.generate_token_secret(60).unwrap();
        assert!(token_authority.is_valid(&token0));

        // Generate token with lifespan of one second.
        let token1 = token_authority.generate_token_secret(1).unwrap();
        assert_eq!(token_authority.num_encrypted_tokens, 2);
        assert!(token_authority.is_valid(&token1));
        // Wait for `token1` to expire.
        sleep(Duration::new(1, 0));
        assert!(!token_authority.is_valid(&token1));
        // The first token should still be valid.
        assert!(token_authority.is_valid(&token0));

        // Simulate reaching to a count of 2^32 encrypted tokens.
        // The cipher and count should reset at this point and previous
        // tokens should become invalid.
        token_authority.num_encrypted_tokens = u32::MAX;
        let token2 = token_authority.generate_token_secret(60).unwrap();
        assert_eq!(token_authority.num_encrypted_tokens, 1);
        assert!(token_authority.is_valid(&token2));
        assert!(!token_authority.is_valid(&token0));
        assert!(!token_authority.is_valid(&token1));
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::EntropyPool(io::Error::from_raw_os_error(0)).to_string(),
            format!(
                "Failed to extract entropy from /dev/urandom entropy pool: {}.",
                io::Error::from_raw_os_error(0)
            )
        );

        assert_eq!(
            Error::ExpiryExtraction.to_string(),
            "Failed to extract expiry value from token."
        );

        assert_eq!(
            Error::InvalidState.to_string(),
            "Invalid token authority state."
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
            Error::Serialization(BincodeError::new(bincode::ErrorKind::SizeLimit)).to_string(),
            "Bincode serialization failed: the size limit has been reached."
        );

        assert_eq!(
            Error::TokenEncryption.to_string(),
            "Failed to encrypt token."
        );
    }
}
