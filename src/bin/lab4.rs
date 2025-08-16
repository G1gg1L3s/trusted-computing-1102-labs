use std::str::FromStr;

use anyhow::Context;
use tss_esapi::{
    TctiNameConf,
    attributes::ObjectAttributesBuilder,
    handles::ObjectHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Auth, CreatePrimaryKeyResult, Digest, EccPoint, EccScheme, HashScheme,
        KeyDerivationFunctionScheme, Public, PublicEccParameters, PublicEccParametersBuilder,
        SymmetricDefinitionObject,
    },
};

fn create_primary(ctx: &mut tss_esapi::Context) -> anyhow::Result<CreatePrimaryKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_st_clear(false)
        .with_admin_with_policy(false)
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

    ctx.create_primary(
        Hierarchy::Owner,
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::default(),
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

        let session = ctx
            .execute_with_sessions((None, None, None), |ctx| {
                ctx.start_auth_session(
                    Some(primary.key_handle),
                    None,
                    None,
                    tss_esapi::constants::SessionType::Hmac,
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

        ctx.execute_with_sessions((Some(AuthSession::Password), Some(session), None), |ctx| {
            let object_attributes = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_sign_encrypt(true)
                .build()
                .unwrap();

            let auth = Auth::try_from(b"sniffmeifyoucan".to_vec()).unwrap();

            let child = ctx
                .create(
                    primary.key_handle,
                    Public::Ecc {
                        object_attributes,
                        name_hashing_algorithm: HashingAlgorithm::Sha256,
                        auth_policy: Default::default(),
                        parameters: PublicEccParametersBuilder::new()
                            .with_curve(EccCurve::NistP256)
                            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(
                                HashingAlgorithm::Sha256,
                            )))
                            .with_is_signing_key(true)
                            .with_restricted(false)
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
                .context("failed to create child")?;

            println!(">> Child private: {:?}", child.out_private);
            println!(">> Child public: {:?}", child.out_public);

            let child_handle = ctx
                .load(primary.key_handle, child.out_private, child.out_public)
                .context("failed to load key")?;

            // let validation = TPMT_TK_HASHCHECK {
            //     tag: TPM2_ST_HASHCHECK,
            //     hierarchy: TPM2_RH_NULL,
            //     digest: Default::default(),
            // };
            // let signature = ctx
            //     .sign(
            //         child_handle,
            //         Digest::try_from([0; 32].as_slice()).unwrap(),
            //         tss_esapi::structures::SignatureScheme::Null,
            //         validation.try_into().unwrap(),
            //     )
            //     .context("failed to sign")?;

            // println!(">> signature: {:?}", signature);

            ctx.flush_context(ObjectHandle::from(primary.key_handle))
                .context("failed to flush parent context")?;

            ctx.flush_context(ObjectHandle::from(child_handle))
                .context("failed to flush child context")?;

            Ok(())
        })
    })?;

    Ok(())
}
