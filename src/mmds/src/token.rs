// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fmt, io};

/// Path to token.
pub const PATH_TO_TOKEN: &str = "/api/token";
/// Length of the token.
pub const TOKEN_LEN: usize = 56;
/// Minimum lifetime of token.
pub const MIN_TOKEN_TTL_SECONDS: u32 = 1;
/// Maximum lifetime of token.
pub const MAX_TOKEN_TTL_SECONDS: u32 = 21600;
/// Randomness pool file path.
const RANDOMNESS_POOL: &str = "/dev/urandom";
/// Maximum number of sessions.
const MAX_SESSIONS: usize = 100;

#[derive(Debug)]
pub enum TokenError {
    /// Failed to open `/dev/urandom` file.
    EntropyPool(io::Error),
    /// Time to live value for token is invalid.
    InvalidTtlValue(u32),
    /// Failed to read from `/dev/urandom` file.
    ReadFromEntropyPool(io::Error),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            TokenError::EntropyPool(err) => write!(f, "Failed to open entropy pool: {}.", err),
            TokenError::InvalidTtlValue(value) => write!(
                f,
                "Invalid time to live value provided for token: {}. \
                Please provide a value between {} and {}.",
                value, MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS,
            ),
            TokenError::ReadFromEntropyPool(err) => {
                write!(f, "Failed to read from entropy pool: {}.", err)
            }
        }
    }
}

#[derive(Debug)]
pub enum TokenStoreError {
    /// Failed to generate session token.
    TokenGenerationError(TokenError),
    /// Session tokens limit exceeded.
    TokensLimitExceeded,
}

impl fmt::Display for TokenStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            TokenStoreError::TokenGenerationError(err) => {
                write!(f, "Failed to generate session token: {}", err)
            }
            TokenStoreError::TokensLimitExceeded => {
                write!(f, "Tokens limit exceeded: {}.", MAX_SESSIONS)
            }
        }
    }
}

/// Structure for information regarding token lifetime.
#[derive(Clone)]
struct TokenTTL {
    ttl_duration: Duration,
    start_time: Instant,
}

impl TokenTTL {
    /// Create a new session Token for MMDS requests.
    fn new(ttl_seconds: u32) -> Self {
        TokenTTL {
            ttl_duration: Duration::from_secs(u64::from(ttl_seconds)),
            start_time: Instant::now(),
        }
    }

    /// Specifies whether the token has expired.
    fn has_expired(&self) -> bool {
        self.start_time.elapsed() >= self.ttl_duration
    }

    /// Validate the token time to live against bounds.
    fn check_ttl(ttl_seconds: u32) -> bool {
        (MIN_TOKEN_TTL_SECONDS..=MAX_TOKEN_TTL_SECONDS).contains(&ttl_seconds)
    }
}

/// Structure for the Token used by MMDSv2.
#[derive(Clone)]
struct Token {
    value: String,
    token_info: TokenTTL,
}

impl Token {
    /// Create a new session Token for MMDS requests.
    fn new(value: String, token_info: TokenTTL) -> Self {
        Token { value, token_info }
    }

    /// Generate a new random token with the specified lifetime.
    fn generate(ttl_seconds: u32) -> Result<Self, TokenError> {
        // Validate token time to live.
        if !TokenTTL::check_ttl(ttl_seconds) {
            return Err(TokenError::InvalidTtlValue(ttl_seconds));
        }

        let mut random_bytes = [0u8; TOKEN_LEN];
        let mut token: String = String::new();
        let mut random_file =
            File::open(Path::new(RANDOMNESS_POOL)).map_err(TokenError::EntropyPool)?;

        while token.len() < TOKEN_LEN {
            let count = random_file
                .read(&mut random_bytes)
                .map_err(TokenError::ReadFromEntropyPool)?;

            // Filter out non alphanumeric characters.
            let random_vec = random_bytes[..count]
                .iter()
                .filter(|x| x.is_ascii_alphanumeric())
                .cloned()
                .collect::<Vec<u8>>();
            if let Ok(str) = String::from_utf8(random_vec) {
                token.push_str(&*str);
            }
        }

        Ok(Self::new(
            token[..TOKEN_LEN].to_string(),
            TokenTTL::new(ttl_seconds),
        ))
    }
}

#[derive(Clone)]
pub struct TokenStore {
    tokens: HashMap<String, TokenTTL>,
}

impl Default for TokenStore {
    fn default() -> Self {
        TokenStore {
            tokens: HashMap::default(),
        }
    }
}

impl TokenStore {
    /// Generate a new token and add it to the store.
    pub fn generate_token(&mut self, ttl_seconds: u32) -> Result<String, TokenStoreError> {
        // Removed expired tokens before adding a new one.
        self.remove_expired();

        // Verify that maximum number of session tokens has not been reached.
        if self.tokens.len() >= MAX_SESSIONS {
            return Err(TokenStoreError::TokensLimitExceeded);
        }

        let token = Token::generate(ttl_seconds).map_err(TokenStoreError::TokenGenerationError)?;
        self.tokens.insert(token.value.clone(), token.token_info);
        Ok(token.value)
    }

    /// Remove expired tokens.
    fn remove_expired(&mut self) {
        self.tokens.retain(|_, info| !info.has_expired())
    }

    /// Specify if the provided token is valid.
    pub fn is_valid(&mut self, token_value: &str) -> bool {
        if let Some(token_info) = self.tokens.get(token_value) {
            if token_info.has_expired() {
                // Remove expired token.
                self.tokens.remove(token_value);
                return false;
            } else {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_generate() {
        // Test valid token generation.
        let ttl_seconds = 60;
        let token = Token::generate(ttl_seconds).unwrap();
        assert!(!token.token_info.has_expired());
        assert_eq!(token.value.len(), TOKEN_LEN);
        assert!(token.value.chars().all(char::is_alphanumeric));

        // Test time to live value too small.
        assert_eq!(
            Token::generate(MIN_TOKEN_TTL_SECONDS - 1)
                .err()
                .unwrap()
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
            Token::generate(MAX_TOKEN_TTL_SECONDS + 1)
                .err()
                .unwrap()
                .to_string(),
            format!(
                "Invalid time to live value provided for token: {}. \
                Please provide a value between {} and {}.",
                MAX_TOKEN_TTL_SECONDS + 1,
                MIN_TOKEN_TTL_SECONDS,
                MAX_TOKEN_TTL_SECONDS
            )
        );
    }

    #[test]
    fn test_has_expired() {
        // Test expired token.
        let token = TokenTTL::new(1);
        sleep(Duration::from_secs(1));
        assert!(token.has_expired());

        // Test valid token.
        let token = TokenTTL::new(1);
        assert!(!token.has_expired());
    }

    #[test]
    fn test_token_store() {
        // Generate token with lifespan of 60 seconds.
        let mut token_store = TokenStore::default();
        let token0 = token_store.generate_token(60).unwrap();
        assert_eq!(token0.len(), TOKEN_LEN);
        assert!(token_store.is_valid(&token0));
        // Token store contains one value.
        assert_eq!(token_store.tokens.len(), 1);
        assert_eq!(
            token_store
                .tokens
                .get(&token0)
                .unwrap()
                .ttl_duration
                .as_secs(),
            60
        );

        // Generate token with lifespan of one second.
        let token1 = token_store.generate_token(1).unwrap();
        let token1_clone = token1.clone();
        assert_eq!(token1.len(), TOKEN_LEN);
        assert!(token_store.is_valid(&token1));
        // Token store contains 2 values.
        assert_eq!(token_store.tokens.len(), 2);
        assert_eq!(
            token_store
                .tokens
                .get(&token1)
                .unwrap()
                .ttl_duration
                .as_secs(),
            1
        );

        // Wait for `token1` to expire.
        sleep(Duration::from_secs(1));
        assert_eq!(token_store.tokens.len(), 2);
        assert!(!token_store.is_valid(&token1_clone));
        // Verify that the expired token has been removed during token validation.
        // Token store now contains only `token0`.
        assert_eq!(token_store.tokens.len(), 1);

        // Generate token with lifespan of one second.
        let token2 = token_store.generate_token(1).unwrap();
        // Token store contains 2 values.
        assert_eq!(token_store.tokens.len(), 2);
        assert_eq!(token2.len(), TOKEN_LEN);
        assert_eq!(
            token_store
                .tokens
                .get(&token2)
                .unwrap()
                .ttl_duration
                .as_secs(),
            1
        );
        assert!(token_store.is_valid(&token2));

        // Wait for token2 to expire.
        sleep(Duration::from_secs(1));
        assert_eq!(token_store.tokens.len(), 2);
        // Generate another token.
        let token3 = token_store.generate_token(20).unwrap();
        // Verify that the expired token has been removed during token generation.
        // Token store now contains only `token0` and `token3`.
        assert_eq!(token_store.tokens.len(), 2);
        assert!(token_store.is_valid(&token3));
    }

    #[test]
    fn test_session_limit_exceeded() {
        let mut token_store = TokenStore::default();

        // Test token limit exceeded.
        for _ in 0..MAX_SESSIONS {
            assert!(token_store.generate_token(2).is_ok());
        }
        assert_eq!(
            token_store.generate_token(2).err().unwrap().to_string(),
            TokenStoreError::TokensLimitExceeded.to_string()
        );
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            TokenStoreError::TokenGenerationError(TokenError::EntropyPool(
                io::Error::from_raw_os_error(0)
            ))
            .to_string(),
            format!(
                "Failed to generate session token: Failed to open entropy pool: {}.",
                io::Error::from_raw_os_error(0)
            )
        );

        assert_eq!(
            TokenStoreError::TokenGenerationError(TokenError::InvalidTtlValue(0)).to_string(),
            format!(
                "Failed to generate session token: Invalid time to live value \
                provided for token: 0. Please provide a value between {} and {}.",
                MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS
            )
        );

        assert_eq!(
            TokenStoreError::TokenGenerationError(TokenError::ReadFromEntropyPool(
                io::Error::from_raw_os_error(0)
            ))
            .to_string(),
            format!(
                "Failed to generate session token: Failed to read from entropy pool: {}.",
                io::Error::from_raw_os_error(0)
            )
        );

        assert_eq!(
            TokenStoreError::TokensLimitExceeded.to_string(),
            "Tokens limit exceeded: 100."
        );
    }
}
