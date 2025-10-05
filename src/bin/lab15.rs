use std::str::FromStr;

use anyhow::Context;
use tss_esapi::{
    TctiNameConf,
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Auth, CreateKeyResult, CreatePrimaryKeyResult, Digest, EccPoint, EccScheme, HashScheme,
        KeyDerivationFunctionScheme, Public, PublicEccParameters, PublicEccParametersBuilder,
        SymmetricDefinitionObject,
    },
};

fn create_primary(ctx: &mut tss_esapi::Context) -> anyhow::Result<CreatePrimaryKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_user_with_auth(false)
        .with_restricted(true)
        .with_decrypt(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_st_clear(false)
        .with_admin_with_policy(true)
        .with_no_da(true)
        .with_encrypted_duplication(false)
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

    let auth = Auth::try_from(b"fuckrussia".as_slice()).unwrap();
    // Generated with lab14
    let auth_policy = Digest::try_from(
        base16ct::mixed::decode_vec(
            b"8FCD2169AB92694E0C633F1AB772842B8241BBC20288981FC7AC1EDDC1FDDB0E",
        )
        .expect("comptime"),
    )
    .expect("comptime");

    ctx.create_primary(
        Hierarchy::Owner,
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy,
            parameters,
            unique: EccPoint::default(),
        },
        Some(auth), // auth_value
        None,       // initial_data
        None,       // outside_info
        None,       // creation_pcrs
    )
    .context("failed to create primary")
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let tcti = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("provide TCTI as a first arg"))?;

    let conf = TctiNameConf::from_str(&tcti).context("failed to parse TCTI")?;
    let mut ctx = tss_esapi::Context::new(conf).context("failed to open context")?;

    ctx.startup(tss_esapi::constants::StartupType::Clear)
        .context("failed to startup")?;

    ctx.tr_set_auth(ObjectHandle::Owner, Auth::try_from(b"".to_vec()).unwrap())
        .context("failed to set auth")?;

    ctx.execute_with_session(Some(AuthSession::Password), |ctx| -> anyhow::Result<()> {
        let primary = create_primary(ctx)?;
        println!(">> Primary: {:?}", primary.out_public);

        ctx.tr_set_auth(
            primary.key_handle.into(),
            Auth::try_from(b"fuckrussia".as_slice()).unwrap(),
        )
        .context("failde to set auth for primary key")?;

        let err = create_child(ctx, primary.key_handle).err();
        println!("Result: {:?}", err);
        Ok(())
    })?;

    Ok(())
}

fn create_child(
    ctx: &mut tss_esapi::Context,
    primary: KeyHandle,
) -> tss_esapi::Result<CreateKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .unwrap();

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
                .with_restricted(false)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .unwrap(),
            unique: EccPoint::default(),
        },
        None, // auth_value,
        None, // sensitive_data,
        None, // outside_info,
        None, // creation_pcrs,
    )
}
