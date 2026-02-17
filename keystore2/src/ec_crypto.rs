// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Implement ECDH-based encryption.

use crate::ks_err;
use anyhow::{Context, Result};
use keystore2_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, ec_key_generate_key, ec_key_get0_public_key,
    ec_key_marshal_private_key, ec_key_parse_private_key, ec_point_oct_to_point,
    ec_point_point_to_oct, ecdh_compute_key, generate_salt, hkdf_expand, hkdf_extract, ECKey,
    EcdhComputeKeyVersion, ZVec, AES_256_KEY_LENGTH,
};

/// Private key for ECDH encryption.
pub struct ECDHPrivateKey(ECKey);

impl ECDHPrivateKey {
    /// Randomly generate a fresh keypair.
    pub fn generate() -> Result<ECDHPrivateKey> {
        ec_key_generate_key().map(ECDHPrivateKey).context(ks_err!("generation failed"))
    }

    /// Deserialize bytes into an ECDH keypair
    pub fn from_private_key(buf: &[u8]) -> Result<ECDHPrivateKey> {
        ec_key_parse_private_key(buf).map(ECDHPrivateKey).context(ks_err!("parsing failed"))
    }

    /// Serialize the ECDH key into bytes
    pub fn private_key(&self) -> Result<ZVec> {
        ec_key_marshal_private_key(&self.0).context(ks_err!("marshalling failed"))
    }

    /// Generate the serialization of the corresponding public key
    pub fn public_key(&self) -> Result<Vec<u8>> {
        let point = ec_key_get0_public_key(&self.0);
        ec_point_point_to_oct(point.get_point()).context(ks_err!("marshalling failed"))
    }

    /// Use ECDH to agree an AES key with another party whose public key we have.
    /// Sender and recipient public keys are passed separately because they are
    /// switched in encryption vs decryption.
    fn agree_key(
        &self,
        salt: &[u8],
        other_public_key: &[u8],
        sender_public_key: &[u8],
        recipient_public_key: &[u8],
        version: EcdhComputeKeyVersion,
    ) -> Result<ZVec> {
        let hkdf = hkdf_extract(sender_public_key, salt)
            .context(ks_err!("hkdf_extract on sender_public_key failed"))?;
        let hkdf = hkdf_extract(recipient_public_key, &hkdf)
            .context(ks_err!("hkdf_extract on recipient_public_key failed"))?;
        let other_public_key = ec_point_oct_to_point(other_public_key)
            .context(ks_err!("ec_point_oct_to_point failed"))?;
        let secret = ecdh_compute_key(other_public_key.get_point(), &self.0, version)
            .context(ks_err!("ecdh_compute_key failed"))?;
        let prk = hkdf_extract(&secret, &hkdf).context(ks_err!("hkdf_extract on secret failed"))?;

        let aes_key = hkdf_expand(AES_256_KEY_LENGTH, &prk, b"AES-256-GCM key")
            .context(ks_err!("hkdf_expand failed"))?;
        Ok(aes_key)
    }

    /// Encrypt a message to the party with the given public key
    pub fn encrypt_message(
        recipient_public_key: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let sender_key = Self::generate().context(ks_err!("generate failed"))?;
        let sender_public_key = sender_key.public_key().context(ks_err!("public_key failed"))?;
        let salt = generate_salt().context(ks_err!("generate_salt failed"))?;
        let aes_key = sender_key
            .agree_key(
                &salt,
                recipient_public_key,
                &sender_public_key,
                recipient_public_key,
                EcdhComputeKeyVersion::Current,
            )
            .context(ks_err!("agree_key failed"))?;
        let (ciphertext, iv, tag) =
            aes_gcm_encrypt(message, &aes_key).context(ks_err!("aes_gcm_encrypt failed"))?;
        Ok((sender_public_key, salt, iv, ciphertext, tag))
    }

    /// Decrypt a message sent to us
    pub fn decrypt_message(
        &self,
        sender_public_key: &[u8],
        salt: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<ZVec> {
        let recipient_public_key = self.public_key()?;
        let aes_key = self
            .agree_key(
                salt,
                sender_public_key,
                sender_public_key,
                &recipient_public_key,
                EcdhComputeKeyVersion::Current,
            )
            .context(ks_err!("agree_key failed"))?;
        aes_gcm_decrypt(ciphertext, iv, tag, &aes_key).or_else(|_e| {
            // Decryption failed.  It could be an old message that was encrypted before the ECDH
            // P-521 output truncation fix, so before failing also try the old derived key.
            let aes_key = self
                .agree_key(
                    salt,
                    sender_public_key,
                    sender_public_key,
                    &recipient_public_key,
                    EcdhComputeKeyVersion::LegacyTruncated,
                )
                .context(ks_err!("agree_key failed"))?;
            aes_gcm_decrypt(ciphertext, iv, tag, &aes_key)
                .context(ks_err!("aes_gcm_decrypt failed"))
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_crypto_roundtrip() -> Result<()> {
        let message = b"Hello world";
        let recipient = ECDHPrivateKey::generate()?;
        let (sender_public_key, salt, iv, ciphertext, tag) =
            ECDHPrivateKey::encrypt_message(&recipient.public_key()?, message)?;
        let recipient = ECDHPrivateKey::from_private_key(&recipient.private_key()?)?;
        let decrypted =
            recipient.decrypt_message(&sender_public_key, &salt, &iv, &ciphertext, &tag)?;
        let dc: &[u8] = &decrypted;
        assert_eq!(message, dc);
        Ok(())
    }

    /// Test that ecdh_compute_key() produces outputs of the expected length.
    #[test]
    fn test_ecdh_output_len() -> Result<()> {
        let sender_key = ECDHPrivateKey::generate()?;
        let recipient_key = ECDHPrivateKey::generate()?;
        let recipient_public_key = ec_point_oct_to_point(&recipient_key.public_key()?)?;
        let secret = ecdh_compute_key(
            recipient_public_key.get_point(),
            &sender_key.0,
            EcdhComputeKeyVersion::Current,
        )?;
        assert_eq!(66, secret.len());
        let secret = ecdh_compute_key(
            recipient_public_key.get_point(),
            &sender_key.0,
            EcdhComputeKeyVersion::LegacyTruncated,
        )?;
        assert_eq!(32, secret.len());
        Ok(())
    }

    /// Test that decrypt_message() can decrypt the output of the old version of encrypt_message().
    /// This is the version that truncated the ECDH P-521 output to 32 bytes.
    #[test]
    fn test_legacy_message_can_be_decrypted() -> Result<()> {
        // These values were originally generated by the old version of encrypt_message(), but they
        // have been hardcoded so that the old encryption code doesn't need to be kept around and so
        // that any incompatible change will be detected.
        let recipient_private_key = [
            48, 71, 2, 1, 1, 4, 66, 0, 72, 60, 178, 143, 102, 7, 200, 247, 69, 6, 54, 113, 101, 20,
            165, 74, 206, 132, 1, 93, 147, 132, 246, 120, 78, 28, 171, 134, 129, 81, 6, 205, 236,
            215, 244, 51, 104, 18, 29, 225, 248, 97, 69, 41, 161, 176, 159, 176, 110, 168, 179,
            186, 244, 86, 53, 215, 99, 243, 183, 136, 8, 46, 46, 42, 103,
        ];
        let recipient = ECDHPrivateKey::from_private_key(&recipient_private_key)?;
        let sender_public_key = [
            4, 1, 164, 126, 44, 228, 92, 140, 86, 90, 31, 239, 87, 60, 45, 29, 247, 159, 108, 183,
            222, 27, 227, 89, 37, 78, 7, 48, 226, 14, 224, 193, 234, 171, 214, 201, 146, 183, 146,
            179, 216, 25, 54, 213, 25, 135, 16, 14, 106, 198, 188, 75, 246, 51, 255, 101, 246, 138,
            255, 83, 120, 205, 160, 106, 207, 45, 235, 1, 173, 67, 13, 241, 108, 93, 25, 36, 220,
            86, 181, 78, 128, 52, 71, 97, 144, 130, 30, 132, 106, 171, 2, 254, 31, 1, 224, 252,
            111, 172, 56, 71, 246, 223, 205, 5, 155, 92, 73, 50, 240, 231, 249, 176, 83, 239, 58,
            141, 174, 211, 30, 164, 142, 227, 154, 156, 222, 131, 64, 57, 39, 53, 207, 202, 124,
        ];
        let salt = [11, 131, 74, 129, 55, 159, 229, 128, 179, 84, 122, 171, 78, 3, 24, 161];
        let iv = [202, 227, 221, 117, 156, 119, 7, 251, 205, 12, 33, 57];
        let ciphertext = [7, 4, 239, 210, 59, 198, 11, 39, 123, 226, 231];
        let tag = [164, 27, 179, 133, 250, 249, 176, 134, 148, 201, 51, 132, 227, 255, 222, 88];
        let message =
            recipient.decrypt_message(&sender_public_key, &salt, &iv, &ciphertext, &tag)?;
        let msg: &[u8] = &message;
        assert_eq!(b"Hello world", msg);
        Ok(())
    }

    /// Test that decrypt_message() can decrypt the output of the current version of
    /// encrypt_message().  This is the version that uses the full ECDH P-521 output.
    #[test]
    fn test_current_message_can_be_decrypted() -> Result<()> {
        // These values were originally generated by encrypt_message(), but they have been hardcoded
        // so that any incompatible change will be detected.
        let recipient_private_key = [
            48, 71, 2, 1, 1, 4, 66, 0, 216, 94, 142, 86, 101, 129, 151, 127, 114, 240, 45, 28, 56,
            43, 44, 252, 219, 19, 57, 133, 209, 161, 60, 194, 143, 94, 110, 26, 106, 99, 103, 49,
            131, 222, 230, 146, 210, 82, 56, 123, 56, 210, 22, 104, 232, 251, 30, 109, 73, 205,
            150, 226, 98, 247, 44, 31, 172, 191, 172, 181, 83, 60, 143, 38, 114,
        ];
        let recipient = ECDHPrivateKey::from_private_key(&recipient_private_key)?;
        let sender_public_key = [
            4, 1, 149, 175, 140, 68, 101, 84, 211, 83, 153, 144, 199, 49, 125, 69, 212, 4, 139,
            192, 205, 151, 214, 23, 212, 10, 104, 147, 127, 52, 177, 33, 78, 18, 42, 221, 3, 185,
            138, 214, 138, 25, 38, 7, 16, 12, 150, 95, 139, 196, 197, 240, 107, 246, 179, 70, 249,
            205, 135, 226, 139, 182, 79, 68, 37, 235, 231, 0, 154, 17, 94, 182, 204, 147, 123, 75,
            150, 171, 203, 180, 126, 98, 177, 72, 156, 86, 28, 172, 138, 151, 47, 90, 246, 69, 76,
            8, 146, 252, 240, 28, 80, 183, 60, 121, 205, 106, 131, 202, 179, 76, 14, 66, 135, 70,
            176, 104, 170, 108, 201, 140, 123, 20, 60, 231, 11, 223, 71, 173, 63, 101, 82, 230, 64,
        ];
        let salt = [198, 36, 146, 129, 103, 221, 7, 77, 143, 143, 152, 194, 246, 56, 181, 189];
        let iv = [97, 196, 14, 111, 173, 36, 59, 38, 13, 215, 172, 100];
        let ciphertext = [116, 97, 162, 238, 173, 96, 82, 13, 9, 186, 99];
        let tag = [92, 109, 104, 137, 163, 115, 202, 63, 116, 122, 243, 125, 0, 77, 192, 135];
        let message =
            recipient.decrypt_message(&sender_public_key, &salt, &iv, &ciphertext, &tag)?;
        let msg: &[u8] = &message;
        assert_eq!(b"Hello world", msg);
        Ok(())
    }
}
