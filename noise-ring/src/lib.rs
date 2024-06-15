#![no_std]

pub mod sensitive;

use cl_noise_protocol::{Cipher, Hash, Unspecified};
use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    digest,
};

pub struct Sha256 {
    context: digest::Context,
}

pub struct Sha512 {
    context: digest::Context,
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256 {
            context: digest::Context::new(&digest::SHA256),
        }
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn name() -> &'static str {
        "SHA256"
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(self) -> Self::Output {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.context.finish().as_ref());
        out
    }
}

impl Default for Sha512 {
    fn default() -> Sha512 {
        Sha512 {
            context: digest::Context::new(&digest::SHA512),
        }
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn name() -> &'static str {
        "SHA512"
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(self) -> Self::Output {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.context.finish().as_ref());
        out
    }
}

const TAGLEN: usize = 16;

pub enum ChaCha20Poly1305 {}

impl Cipher for ChaCha20Poly1305 {
    fn name() -> &'static str {
        "ChaChaPoly"
    }

    type Key = LessSafeKey;

    fn key_len() -> usize {
        aead::CHACHA20_POLY1305.key_len()
    }

    fn key_from_slice(b: &[u8]) -> Self::Key {
        LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, b).unwrap())
    }

    fn encrypt(key: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert!(plaintext.len().checked_add(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let (in_out, tag_out) = out.split_at_mut(plaintext.len());
        in_out.copy_from_slice(plaintext);

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());
    }

    fn encrypt_in_place(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize {
        assert!(plaintext_len
            .checked_add(TAGLEN)
            .map_or(false, |l| l <= in_out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let (in_out, tag_out) = in_out[..plaintext_len + TAGLEN].split_at_mut(plaintext_len);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());

        plaintext_len + TAGLEN
    }

    fn decrypt(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Unspecified> {
        assert!(ciphertext.len().checked_sub(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext.to_vec();

        let out0 = key
            .open_in_place(nonce, aead::Aad::from(ad), &mut in_out)
            .map_err(|_| Unspecified)?;

        out[..out0.len()].copy_from_slice(out0);
        Ok(())
    }

    fn decrypt_in_place(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Unspecified> {
        assert!(ciphertext_len <= in_out.len());
        assert!(ciphertext_len >= TAGLEN);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        key.open_in_place(nonce, aead::Aad::from(ad), &mut in_out[..ciphertext_len])
            .map_err(|_| Unspecified)?;

        Ok(ciphertext_len - TAGLEN)
    }
}

pub enum Aes256Gcm {}

impl Cipher for Aes256Gcm {
    fn name() -> &'static str {
        "AESGCM"
    }

    type Key = LessSafeKey;

    fn key_len() -> usize {
        aead::AES_256_GCM.key_len()
    }

    fn key_from_slice(b: &[u8]) -> Self::Key {
        LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, b).unwrap())
    }

    fn encrypt(key: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert!(plaintext.len().checked_add(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let (in_out, tag_out) = out.split_at_mut(plaintext.len());
        in_out.copy_from_slice(plaintext);

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());
    }

    fn encrypt_in_place(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize {
        assert!(plaintext_len
            .checked_add(TAGLEN)
            .map_or(false, |l| l <= in_out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let (in_out, tag_out) = in_out[..plaintext_len + TAGLEN].split_at_mut(plaintext_len);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());

        plaintext_len + TAGLEN
    }

    fn decrypt(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Unspecified> {
        assert!(ciphertext.len().checked_sub(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext.to_vec();

        let out0 = key
            .open_in_place(nonce, aead::Aad::from(ad), &mut in_out)
            .map_err(|_| Unspecified)?;

        out[..out0.len()].copy_from_slice(out0);
        Ok(())
    }

    fn decrypt_in_place(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Unspecified> {
        assert!(ciphertext_len <= in_out.len());
        assert!(ciphertext_len >= TAGLEN);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        key.open_in_place(nonce, aead::Aad::from(ad), &mut in_out[..ciphertext_len])
            .map_err(|_| Unspecified)?;

        Ok(ciphertext_len - TAGLEN)
    }
}
