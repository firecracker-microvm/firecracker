// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::fmt;
use std::ops::Add;

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use base64::Engine;
use serde::{Deserialize, Serialize};
use utils::time::{ClockType, get_time_ms};

/// Length of initialization vector.
pub const IV_LEN: usize = 12;
/// Length of the key used for encryption.
pub const KEY_LEN: usize = 32;
/// Length of encryption payload.
pub const PAYLOAD_LEN: usize = std::mem::size_of::<u64>();
/// Length of encryption tag.
pub const TAG_LEN: usize = 16;

/// Maximum size in bytes for token deserialization to prevent DOS attacks.
/// The Token struct contains fixed-size arrays (IV_LEN + PAYLOAD_LEN + TAG_LEN = 36 bytes)
/// plus bitcode serialization overhead. This limit provides a safe margin.
const TOKEN_DESERIALIZATION_BYTES_LIMIT: usize = 100;

/// Constant to convert seconds to milliseconds.
pub const MILLISECONDS_PER_SECOND: u64 = 1_000;

/// Minimum lifetime of token.
pub const MIN_TOKEN_TTL_SECONDS: u32 = 1;
/// Maximum lifetime of token.
pub const MAX_TOKEN_TTL_SECONDS: u32 = 21600;

/// Path to token.
pub const PATH_TO_TOKEN: &str = "/latest/api/token";

/// Token length limit to ensure we don't bother decrypting huge character
/// sequences. Tokens larger than this are automatically rejected. The value
/// is computed based on the expected length of the base64 encoded Token struct
/// including a small deviation.
const TOKEN_LENGTH_LIMIT: usize = 70;

#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MmdsTokenError {
    /// Failed to generate a key
    KeyGeneration,
    /// Failed to extract expiry value from token.
    ExpiryExtraction,
    /// Invalid time to live value provided for token: {0}. Please provide a value between {MIN_TOKEN_TTL_SECONDS:} and {MAX_TOKEN_TTL_SECONDS:}.
    InvalidTtlValue(u32),
    /// Bitcode serialization failed: {0}.
    Serialization(#[from] bitcode::Error),
    /// Failed to encrypt token.
    TokenEncryption,
}

pub struct TokenAuthority {
    cipher: RandomizedNonceKey,
    // Number of tokens encrypted under the current key.
    num_encrypted_tokens: u32,
    // Additional Authentication Data used for encryption and decryption.
    aad: String,
}
// TODO When https://github.com/RustCrypto/AEADs/pull/532 is merged replace these manual
// implementation with `#[derive(Debug)]`.
impl fmt::Debug for TokenAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenAuthority")
            .field("num_encrypted_tokens", &self.num_encrypted_tokens)
            .field("aad", &self.aad)
            .finish()
    }
}

impl TokenAuthority {
    /// Create a new token authority entity.
    pub fn try_new() -> Result<TokenAuthority, MmdsTokenError> {
        Ok(TokenAuthority {
            cipher: TokenAuthority::create_cipher()?,
            num_encrypted_tokens: 0,
            aad: "".to_string(),
        })
    }

    /// Set Additional Authenticated Data to be used for
    /// encryption and decryption of the session token.
    pub fn set_aad(&mut self, instance_id: &str) {
        self.aad = format!("microvmid={}", instance_id);
    }

    /// Generate encoded token string using the token time to live provided.
    pub fn generate_token_secret(&mut self, ttl_seconds: u32) -> Result<String, MmdsTokenError> {
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
    fn create_token(&mut self, ttl_seconds: u32) -> Result<Token, MmdsTokenError> {
        // Validate token time to live against bounds.
        if !TokenAuthority::check_ttl(ttl_seconds) {
            return Err(MmdsTokenError::InvalidTtlValue(ttl_seconds));
        }

        // Compute expiration time in milliseconds from ttl.
        let expiry = TokenAuthority::compute_expiry(ttl_seconds);
        // Encrypt expiry (RandomizedNonceKey generates nonce automatically).
        self.encrypt_expiry(expiry)
    }

    /// Encrypt expiry using AES-GCM block cipher and return token obtained.
    fn encrypt_expiry(&self, expiry: u64) -> Result<Token, MmdsTokenError> {
        // Convert expiry u64 value into bytes.
        let mut expiry_as_bytes = expiry.to_le_bytes();
        let aad = Aad::from(self.aad.as_bytes());

        let (nonce, tag) = self
            .cipher
            .seal_in_place_separate_tag(aad, &mut expiry_as_bytes)
            .map_err(|_| MmdsTokenError::TokenEncryption)?;

        // Tag must be of size `TAG_LEN`.
        let tag_as_bytes: [u8; TAG_LEN] = tag
            .as_ref()
            .try_into()
            .map_err(|_| MmdsTokenError::TokenEncryption)?;

        Ok(Token::new(*nonce.as_ref(), expiry_as_bytes, tag_as_bytes))
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
        let token = match Token::base64_decode(encoded_token) {
            Ok(token) => token,
            Err(_) => return false,
        };

        // Decrypt ttl using AES-GCM block cipher.
        let expiry = match self.decrypt_expiry(&token) {
            Ok(expiry) => expiry,
            Err(_) => return false,
        };

        // Compare expiry (in ms) with current time in milliseconds.
        expiry > get_time_ms(ClockType::Monotonic)
    }

    /// Decrypt ciphertext composed of payload and tag to obtain the expiry value.
    fn decrypt_expiry(&self, token: &Token) -> Result<u64, MmdsTokenError> {
        // Create Nonce object from initialization vector.
        let nonce = Nonce::assume_unique_for_key(token.iv);
        let aad = Aad::from(self.aad.as_bytes());

        // Combine payload and tag for aws-lc-rs
        let mut ciphertext_and_tag = [0; PAYLOAD_LEN + TAG_LEN];
        ciphertext_and_tag[..PAYLOAD_LEN].copy_from_slice(&token.payload);
        ciphertext_and_tag[PAYLOAD_LEN..].copy_from_slice(&token.tag);

        // Decrypt in place
        let plaintext = self
            .cipher
            .open_in_place(nonce, aad, &mut ciphertext_and_tag)
            .map_err(|_| MmdsTokenError::ExpiryExtraction)?;

        let expiry_as_bytes: [u8; PAYLOAD_LEN] = plaintext
            .try_into()
            .map_err(|_| MmdsTokenError::ExpiryExtraction)?;

        // Return expiry value in seconds.
        Ok(u64::from_le_bytes(expiry_as_bytes))
    }

    /// Create a new AES-GCM cipher entity.
    fn create_cipher() -> Result<RandomizedNonceKey, MmdsTokenError> {
        // Randomly generate a 256-bit key to be used for encryption/decryption purposes.
        let mut key = [0u8; KEY_LEN];
        aws_lc_rs::rand::fill(&mut key).map_err(|_| MmdsTokenError::KeyGeneration)?;

        // Create cipher entity to handle encryption/decryption.
        RandomizedNonceKey::new(&AES_256_GCM, &key).map_err(|_| MmdsTokenError::KeyGeneration)
    }

    /// Make sure to reinitialize the cipher under a new key before reaching
    /// a count of 2^32 encrypted tokens under the same cipher entity.
    fn check_encryption_count(&mut self) -> Result<(), MmdsTokenError> {
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
            self.cipher = TokenAuthority::create_cipher()?;
            // Reset encrypted tokens count.
            self.num_encrypted_tokens = 0;
            crate::logger::warn!(
                "The limit of tokens generated under current MMDS token authority
                has been reached. MMDS's token authority entity has been reseeded
                and all previously created tokens are now invalid."
            );
        }

        Ok(())
    }

    /// Validate the token time to live against bounds.
    fn check_ttl(ttl_seconds: u32) -> bool {
        (MIN_TOKEN_TTL_SECONDS..=MAX_TOKEN_TTL_SECONDS).contains(&ttl_seconds)
    }

    /// Compute expiry time in seconds by adding the time to live provided
    /// to the current time measured in milliseconds.
    fn compute_expiry(ttl_as_seconds: u32) -> u64 {
        // Get current time in milliseconds.
        let now_as_milliseconds = get_time_ms(ClockType::Monotonic);

        // Compute expiry by adding ttl value converted to milliseconds
        // to current time (also in milliseconds). This addition is safe
        // because ttl is verified beforehand and can never be more than
        // 6h (21_600_000 ms).
        now_as_milliseconds.add(u64::from(ttl_as_seconds) * MILLISECONDS_PER_SECOND)
    }
}

/// Structure for token information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
    fn base64_encode(&self) -> Result<String, MmdsTokenError> {
        let token_bytes: Vec<u8> = bitcode::serialize(self)?;

        // Encode token structure bytes into base64.
        Ok(base64::engine::general_purpose::STANDARD.encode(token_bytes))
    }

    /// Decode token structure from base64 string.
    fn base64_decode(encoded_token: &str) -> Result<Self, MmdsTokenError> {
        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_token)
            .map_err(|_| MmdsTokenError::ExpiryExtraction)?;

        // Check size limit to prevent DOS attacks
        if token_bytes.len() > TOKEN_DESERIALIZATION_BYTES_LIMIT {
            return Err(MmdsTokenError::ExpiryExtraction);
        }

        let token: Token =
            bitcode::deserialize(&token_bytes).map_err(|_| MmdsTokenError::ExpiryExtraction)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

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
        let mut token_authority = TokenAuthority::try_new().unwrap();
        assert_eq!(token_authority.aad, "".to_string());

        token_authority.set_aad("foo");
        assert_eq!(token_authority.aad, "microvmid=foo".to_string());
    }

    #[test]
    fn test_create_token() {
        let mut token_authority = TokenAuthority::try_new().unwrap();

        // Test invalid time to live value.
        assert_eq!(
            token_authority.create_token(0).unwrap_err().to_string(),
            format!(
                "Invalid time to live value provided for token: 0. Please provide a value between \
                 {} and {}.",
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
        let time_now = get_time_ms(ClockType::Monotonic);
        let expiry = TokenAuthority::compute_expiry(1);
        let ttl = expiry - time_now;
        // We allow a deviation of 20ms to account for the gap
        // between the two calls to `get_time_ms()`.
        let deviation = 20;
        assert!(
            ttl >= MILLISECONDS_PER_SECOND && ttl <= MILLISECONDS_PER_SECOND + deviation,
            "ttl={ttl} not within [{MILLISECONDS_PER_SECOND}, \
             {MILLISECONDS_PER_SECOND}+{deviation}]",
        );

        let time_now = get_time_ms(ClockType::Monotonic);
        let expiry = TokenAuthority::compute_expiry(0);
        let ttl = expiry - time_now;
        assert!(ttl <= deviation, "ttl={ttl} is greater than {deviation}");
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut token_authority = TokenAuthority::try_new().unwrap();
        let expiry = TokenAuthority::compute_expiry(10);

        // Test valid ciphertext.
        let token = token_authority.encrypt_expiry(expiry).unwrap();
        let decrypted_expiry = token_authority.decrypt_expiry(&token).unwrap();
        assert_eq!(expiry, decrypted_expiry);

        // Test ciphertext with corrupted payload.
        let mut bad_token = token.clone();
        bad_token.payload[0] = u8::MAX - bad_token.payload[0];
        assert!(matches!(
            token_authority.decrypt_expiry(&bad_token).unwrap_err(),
            MmdsTokenError::ExpiryExtraction
        ));

        // Test ciphertext with corrupted tag.
        let mut bad_token = token.clone();
        bad_token.tag[0] = u8::MAX - bad_token.tag[0];
        assert!(matches!(
            token_authority.decrypt_expiry(&bad_token).unwrap_err(),
            MmdsTokenError::ExpiryExtraction
        ));

        // Test decrypting expiry under a different AAD than it was encrypted with.
        token_authority.set_aad("foo");
        assert!(matches!(
            token_authority.decrypt_expiry(&token).unwrap_err(),
            MmdsTokenError::ExpiryExtraction
        ));
    }

    #[test]
    fn test_encode_decode() {
        let expected_token = Token::new([0u8; IV_LEN], [0u8; PAYLOAD_LEN], [0u8; TAG_LEN]);
        let mut encoded_token = expected_token.base64_encode().unwrap();
        let actual_token = Token::base64_decode(&encoded_token).unwrap();
        assert_eq!(actual_token, expected_token);

        // Decode invalid base64 bytes sequence.
        encoded_token.push('x');
        Token::base64_decode(&encoded_token).unwrap_err();
    }

    #[test]
    fn test_generate_token_secret() {
        let mut token_authority = TokenAuthority::try_new().unwrap();

        // Test time to live value too small.
        assert_eq!(
            token_authority
                .generate_token_secret(MIN_TOKEN_TTL_SECONDS - 1)
                .unwrap_err()
                .to_string(),
            format!(
                "Invalid time to live value provided for token: {}. Please provide a value \
                 between {} and {}.",
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
                "Invalid time to live value provided for token: {}. Please provide a value \
                 between {} and {}.",
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
        let mut token_authority = TokenAuthority::try_new().unwrap();

        // Test token with size bigger than expected.
        assert!(!token_authority.is_valid(str::repeat("a", TOKEN_LENGTH_LIMIT + 1).as_str()));

        // Test valid token.
        let token0 = token_authority.generate_token_secret(1).unwrap();
        assert!(token_authority.is_valid(&token0));
    }

    #[test]
    fn test_token_authority() {
        let mut token_authority = TokenAuthority::try_new().unwrap();

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
}
