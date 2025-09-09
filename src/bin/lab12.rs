use std::str::FromStr;

use anyhow::Context;
use p256::{
    ecdsa::{self, signature},
    elliptic_curve::sec1::FromEncodedPoint,
};
use tss_esapi::{
    TctiNameConf,
    attributes::ObjectAttributesBuilder,
    handles::{AuthHandle, KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Attest, Auth, CreateKeyResult, CreatePrimaryKeyResult, Data, Digest, EccParameter,
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Nonce, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, Public, PublicEccParameters, PublicEccParametersBuilder,
        Signature, SignatureScheme, SymmetricDefinitionObject,
    },
    traits::Marshall,
};

enum AlgoType {
    P256,
    P384,
}

impl std::str::FromStr for AlgoType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            unknown => anyhow::bail!("unknown string: {:?}", unknown),
        }
    }
}

/// <https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf#page=44>
fn create_ek_low_p256(ctx: &mut tss_esapi::Context) -> anyhow::Result<CreatePrimaryKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_st_clear(false)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_no_da(false)
        .with_encrypted_duplication(false)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .unwrap();

    let parameters = PublicEccParameters::builder()
        .with_curve(EccCurve::NistP256)
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cfb,
        })
        .with_ecc_scheme(EccScheme::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()
        .unwrap();

    let empty_value = EccParameter::try_from(&[0; 32][..]).unwrap();

    ctx.create_primary(
        Hierarchy::Endorsement,
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::try_from(
                &[
                    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46,
                    0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1,
                    0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
                ][..],
            )
            .unwrap(),
            parameters,
            unique: EccPoint::new(empty_value.clone(), empty_value),
        },
        None, // auth_value
        None, // initial_data
        None, // outside_info
        None, // creation_pcrs
    )
    .context("failed to create primary")
}

/// <https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf#page=49>
fn create_ek_hi_p384(ctx: &mut tss_esapi::Context) -> anyhow::Result<CreatePrimaryKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_st_clear(false)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_admin_with_policy(true)
        .with_no_da(false)
        .with_encrypted_duplication(false)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .unwrap();

    let parameters = PublicEccParameters::builder()
        .with_curve(EccCurve::NistP384)
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes256,
            mode: SymmetricMode::Cfb,
        })
        .with_ecc_scheme(EccScheme::Null)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()
        .unwrap();

    ctx.create_primary(
        Hierarchy::Endorsement,
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm: HashingAlgorithm::Sha384,
            auth_policy: Digest::try_from(
                &[
                    0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC, 0xF5,
                    0xFD, 0x3A, 0x1A, 0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4, 0xCB, 0x1C,
                    0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46,
                    0x15, 0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
                ][..],
            )
            .unwrap(),
            parameters,
            unique: EccPoint::default(),
        },
        None, // auth_value
        None, // initial_data
        None, // outside_info
        None, // creation_pcrs
    )
    .context("failed to create primary")
}

fn create_child(
    ctx: &mut tss_esapi::Context,
    primary: KeyHandle,
) -> anyhow::Result<CreateKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .build()
        .unwrap();

    let auth = Auth::try_from(b"sniffmeifyoucan".to_vec()).unwrap();

    ctx.create(
        primary,
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Default::default(),
            parameters: PublicEccParametersBuilder::new()
                .with_curve(EccCurve::NistP256)
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_is_signing_key(true)
                .with_restricted(true)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .unwrap(),
            unique: EccPoint::default(),
        },
        Some(auth), // auth_value,
        None,       // sensitive_data,
        None,       // outside_info,
        None,       // creation_pcrs,
    )
    .context("failed to create child")
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let tcti = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("provide TCTI as a first arg"))?;

    let algo_type = std::env::args()
        .nth(2)
        .map(|s| s.parse::<AlgoType>())
        .transpose()
        .context("failed to parse algo type")?
        .unwrap_or(AlgoType::P256);

    let conf = TctiNameConf::from_str(&tcti).context("failed to parse TCTI")?;
    let mut ctx = tss_esapi::Context::new(conf).context("failed to open context")?;

    ctx.startup(tss_esapi::constants::StartupType::Clear)
        .context("failed to startup")?;

    ctx.tr_set_auth(ObjectHandle::Owner, Auth::try_from(b"".to_vec()).unwrap())
        .context("failed to set auth")?;

    ctx.tr_set_auth(
        ObjectHandle::Endorsement,
        Auth::try_from(b"".to_vec()).unwrap(),
    )
    .context("failed to set endorsement auth")?;

    ctx.execute_with_session(Some(AuthSession::Password), |ctx| -> anyhow::Result<()> {
        let primary = match algo_type {
            AlgoType::P256 => create_ek_low_p256(ctx)?,
            AlgoType::P384 => create_ek_hi_p384(ctx)?,
        };

        let Public::Ecc { unique, .. } = primary.out_public else {
            anyhow::bail!(
                "create primary didn't return ecc key: {:?}",
                primary.out_public
            );
        };

        let sec1 = match algo_type {
            AlgoType::P256 => ecc_point_to_p256_key(&unique)
                .context("failed to parse ECC key")?
                .to_sec1_bytes(),
            AlgoType::P384 => ecc_point_to_p384_key(&unique)
                .context("failed to parse ECC key")?
                .to_sec1_bytes(),
        };

        println!(">> Ek:\n{}", AsOpensslKey(&sec1));

        let session = ctx
            .execute_with_sessions((None, None, None), |ctx| {
                ctx.start_auth_session(
                    Some(primary.key_handle),
                    None,
                    None,
                    tss_esapi::constants::SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::AES_128_CFB,
                    HashingAlgorithm::Sha256,
                )
                .map(|session| session.expect("session should not be none"))
            })
            .context("failed to start session")?;

        let (session_attr, session_attr_mask) = tss_esapi::attributes::SessionAttributes::builder()
            .with_decrypt(true)
            .with_encrypt(true)
            .with_continue_session(true)
            .build();

        ctx.tr_sess_set_attributes(session, session_attr, session_attr_mask)
            .context("failed to set session attributes")?;

        ctx.execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
            ctx.policy_secret(
                PolicySession::try_from(session)
                    .expect("Failed to convert auth session to policy session"),
                AuthHandle::Endorsement,
                Nonce::default(),
                Digest::default(), // cp_hash_a,
                Nonce::default(),  // policy_ref,
                None,              // expiration,
            )
            .context("failed to execute policy secret 1")
        })?;

        ctx.execute_with_sessions((Some(session), None, None), |ctx| -> anyhow::Result<()> {
            let child = create_child(ctx, primary.key_handle).context("failed to create child")?;

            let Public::Ecc { unique, .. } = &child.out_public else {
                anyhow::bail!("create child didn't return ecc key: {:?}", child.out_public);
            };
            let attestation_key =
                ecc_point_to_p256_key(unique).context("failed to parse child key")?;
            println!(
                ">> Child:\n{}",
                AsOpensslKey(&attestation_key.to_sec1_bytes())
            );

            ctx.execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
                ctx.policy_secret(
                    PolicySession::try_from(session)
                        .expect("Failed to convert auth session to policy session"),
                    AuthHandle::Endorsement,
                    Nonce::default(),
                    Digest::default(), // cp_hash_a,
                    Nonce::default(),  // policy_ref,
                    None,              // expiration,
                )
                .context("failed to execute policy secret 2")
            })?;

            let child_handle = ctx
                .load(primary.key_handle, child.out_private, child.out_public)
                .context("failed to load child key")?;
            println!(">> Child handle: {:?}", child_handle);

            ctx.tr_set_auth(
                ObjectHandle::from(child_handle),
                Auth::try_from(b"sniffmeifyoucan".to_vec()).unwrap(),
            )
            .context("failed to set tr_auth")?;

            let (attest, signature) =
                ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
                    ctx.quote(
                        child_handle,
                        Data::default(),
                        SignatureScheme::Null,
                        PcrSelectionListBuilder::new()
                            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot23])
                            .build()
                            .expect("must be ok"),
                    )
                    .context("failed to quote")
                })?;

            verify_attestation_signature(attestation_key.into(), &attest, &signature)?;
            println!(">> Signature verification: OK");
            println!(">> Attest info: {:?}", attest.attested());
            println!(">> Signer: {:?}", attest.qualified_signer());
            println!(">> Extra data: {:?}", attest.extra_data());
            println!(">> Clock info: {:?}", attest.clock_info());
            println!(">> Firmware Version: {:?}", attest.firmware_version());

            ctx.flush_context(ObjectHandle::from(child_handle))
                .context("failed to flush child context")?;

            Ok(())
        })?;

        ctx.flush_context(ObjectHandle::from(primary.key_handle))
            .context("failed to flush parent context")?;

        Ok(())
    })
}

fn ecc_point_to_p256_key(ecc: &EccPoint) -> anyhow::Result<p256::PublicKey> {
    let x = ecc.x().as_slice();
    let y = ecc.y().as_slice();

    let (32, 32) = (x.len(), y.len()) else {
        anyhow::bail!("coordinates are of the wrong length");
    };

    let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);

    p256::PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("failed to create P256 pubkey"))
}

fn ecc_point_to_p384_key(ecc: &EccPoint) -> anyhow::Result<p384::PublicKey> {
    let x = ecc.x().as_slice();
    let y = ecc.y().as_slice();

    let (48, 48) = (x.len(), y.len()) else {
        anyhow::bail!("coordinates are of the wrong length");
    };

    let point = p384::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);

    p384::PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("failed to create P256 pubkey"))
}

fn verify_attestation_signature(
    ak_pub: ecdsa::VerifyingKey,
    attest: &Attest,
    signature: &Signature,
) -> anyhow::Result<()> {
    use ecdsa::signature::Verifier;

    let Signature::EcDsa(signature) = signature else {
        anyhow::bail!("signature is of wrong type: {:?}", signature);
    };

    match signature.hashing_algorithm() {
        HashingAlgorithm::Sha256 => {}
        sig => anyhow::bail!("wrong hashing algo for signature: {sig:?}"),
    }

    let r: &[u8; 32] = signature
        .signature_r()
        .as_slice()
        .try_into()
        .context("r is not 32 bytes")?;

    let s: &[u8; 32] = signature
        .signature_s()
        .as_slice()
        .try_into()
        .context("s is not 32 bytes")?;

    let signature =
        ecdsa::Signature::from_scalars(*r, *s).context("failed to construct signature")?;

    let marshalled = attest.marshall().context("failed to marshall")?;

    ak_pub
        .verify(&marshalled, &signature)
        .context("failed to verify signature")?;

    Ok(())
}

#[derive(Debug)]
struct AsOpensslKey<'a>(&'a [u8]);

impl<'a> std::fmt::Display for AsOpensslKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for chunk in self.0.chunks(15) {
            for b in chunk {
                write!(f, "{:02x}:", b)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
