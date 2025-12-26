// Copyright 2025, The Android Open Source Project
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

//! Basic test of ML-DSA functionality.
//!
//! Only minimal testing is required because `keystore2` passes through all ML-DSA
//! functionality to KeyMint (i.e. there is no software emulation).

use crate::keystore2_client_test_utils::{delete_app_key, perform_sample_sign_operation};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, MlDsaVariant::MlDsaVariant,
    Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use keystore2_test_utils::{
    authorizations::{self, AuthSetBuilder},
    key_generations, SecLevel,
};
use keystore_attestation::{AttestationExtension, ATTESTATION_EXTENSION_OID};
use x509_cert::{certificate::Certificate, der::Decode};

#[test]
fn test_mldsa_generate_sign() {
    let sl = SecLevel::tee();
    if sl.get_keymint_version() < 5 {
        // ML-DSA support only present on KeyMint >= v5
        return;
    }

    let alias = "generated_mldsa_key";
    let metadata = key_generations::generate_mldsa_key(
        &sl,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        MlDsaVariant::ML_DSA_65,
    )
    .unwrap();
    let op_rsp = sl
        .binder
        .createOperation(
            &metadata.key,
            &AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::NONE),
            false,
        )
        .unwrap();
    let op = op_rsp.iOperation.unwrap();

    assert_eq!(Ok(()), key_generations::map_ks_error(perform_sample_sign_operation(&op)));

    delete_app_key(&sl.keystore2, alias).unwrap();
}

#[test]
fn test_mldsa_import_sign() {
    const MLDSA_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let sl = SecLevel::tee();
    if sl.get_keymint_version() < 5 {
        // ML-DSA support only present on KeyMint >= v5
        return;
    }

    let alias = "imported_mldsa_key";
    let import_params = AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::ML_DSA)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(Digest::NONE)
        .mldsa_variant(MlDsaVariant::ML_DSA_65);

    let metadata = sl
        .binder
        .importKey(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(alias.to_string()),
                blob: None,
            },
            None,
            &import_params,
            0,
            &MLDSA_SEED,
        )
        .unwrap();

    let op_rsp = sl
        .binder
        .createOperation(
            &metadata.key,
            &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::NONE),
            false,
        )
        .unwrap();
    let op = op_rsp.iOperation.unwrap();

    assert_eq!(Ok(()), key_generations::map_ks_error(perform_sample_sign_operation(&op)));

    delete_app_key(&sl.keystore2, alias).unwrap();
}

#[test]
fn test_mldsa_generate_attested() {
    let sl = SecLevel::tee();
    if sl.get_keymint_version() < 5 {
        // ML-DSA support only present on KeyMint >= v5
        return;
    }

    let alias = "generated_mldsa_key";
    let metadata = key_generations::generate_attested_mldsa_key(
        &sl,
        Domain::APP,
        -1,
        Some(alias.to_string()),
        MlDsaVariant::ML_DSA_65,
    )
    .unwrap();
    assert!(metadata.certificateChain.is_some());

    let cert_data = metadata.certificate.as_ref().unwrap();
    let cert = Certificate::from_der(cert_data).expect("failed to parse X509 cert");
    assert_eq!(
        cert.tbs_certificate.subject_public_key_info.algorithm.oid,
        // OID value from draft-ietf-lamps-dilithium-certificates-13 section 2
        x509_cert::spki::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18")
    );
    let exts = cert.tbs_certificate.extensions.expect("no X.509 extensions");
    let ext = exts
        .iter()
        .find(|ext| ext.extn_id == ATTESTATION_EXTENSION_OID)
        .expect("no attestation extension");
    let ext = AttestationExtension::from_der(ext.extn_value.as_bytes())
        .expect("failed to parse attestation extension");

    let alg = ext.hw_enforced.auths.iter().find_map(|kp| {
        if let KeyParameter { tag: Tag::ALGORITHM, value: KeyParameterValue::Algorithm(alg) } = kp {
            Some(*alg)
        } else {
            None
        }
    });
    assert_eq!(alg, Some(Algorithm::ML_DSA));

    let variant = ext.hw_enforced.auths.iter().find_map(|kp| {
        if let KeyParameter {
            tag: Tag::ML_DSA_VARIANT,
            value: KeyParameterValue::MlDsaVariant(variant),
        } = kp
        {
            Some(*variant)
        } else {
            None
        }
    });
    assert_eq!(variant, Some(MlDsaVariant::ML_DSA_65));

    delete_app_key(&sl.keystore2, alias).unwrap();
}
