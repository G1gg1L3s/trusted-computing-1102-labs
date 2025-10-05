use std::str::FromStr;

use anyhow::{Context, anyhow};
use tss_esapi::{
    TctiNameConf,
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Auth, CreateKeyResult, CreatePrimaryKeyResult, Digest, EccPoint, EccScheme,
        KeyDerivationFunctionScheme, KeyedHashScheme, PcrSelectionListBuilder, PcrSlot, Public,
        PublicEccParameters, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
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
        .ok_or_else(|| anyhow!("provide TCTI as a first arg"))?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot23])
        .build()
        .expect("static");

    let conf = TctiNameConf::from_str(&tcti).context("failed to parse TCTI")?;
    let mut ctx = tss_esapi::Context::new(conf).context("failed to open context")?;

    ctx.startup(tss_esapi::constants::StartupType::Clear)
        .context("failed to startup")?;

    ctx.tr_set_auth(ObjectHandle::Owner, Auth::try_from(b"".to_vec()).unwrap())
        .context("failed to set auth")?;

    let policy_digest = ctx.execute_without_session(|ctx| -> anyhow::Result<_> {
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .context("failed to start trial session")?
            .ok_or_else(|| anyhow!("no trial session returned"))?;

        let policy_session = session
            .try_into()
            .context("failed to convert session to policy session")?;

        ctx.policy_pcr(policy_session, Digest::default(), pcr_selection.clone())
            .context("failed to execute policy pcr on trial session")?;

        let digest = ctx
            .policy_get_digest(policy_session)
            .context("failed to get digest")?;

        let PolicySession::PolicySession { session_handle, .. } = policy_session;

        ctx.flush_context(session_handle.into())
            .context("failed to flush context")?;

        Ok(digest)
    })?;

    let key =
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| -> anyhow::Result<_> {
            let primary = create_primary(ctx)?;
            println!(">> Primary: {:?}", primary.out_public);

            let key_result = create_child(ctx, primary.key_handle, policy_digest)
                .context("failed to create child")?;
            let key = ctx
                .load(
                    primary.key_handle,
                    key_result.out_private,
                    key_result.out_public,
                )
                .context("failed to load key")?;

            ctx.flush_context(primary.key_handle.into())
                .context("failed to flush primary")?;

            Ok(key)
        })?;

    ctx.execute_without_session(|ctx| {
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .context("failed to start policy session")?
            .ok_or_else(|| anyhow!("returned empty session"))?;

        let AuthSession::PolicySession(policy_session) = session else {
            anyhow::bail!("received unexpected session type: {:?}", session);
        };

        ctx.policy_pcr(policy_session, Digest::default(), pcr_selection)
            .context("failed to get policy_pcr")?;

        let value = ctx
            .execute_with_session(Some(session), |ctx| ctx.unseal(key.into()))
            .context("failed to unseal")?;

        println!("Value: {:?}", str::from_utf8(value.as_slice()));

        Ok(())
    })?;

    Ok(())
}

fn create_child(
    ctx: &mut tss_esapi::Context,
    primary: KeyHandle,
    policy: Digest,
) -> tss_esapi::Result<CreateKeyResult> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_admin_with_policy(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(false)
        .with_user_with_auth(false)
        .with_sign_encrypt(false)
        .build()
        .unwrap();

    ctx.create(
        primary,
        Public::KeyedHash {
            object_attributes,
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: policy,
            parameters: PublicKeyedHashParameters::new(KeyedHashScheme::Null),
            unique: Default::default(),
        },
        None, // auth_value,
        Some(SensitiveData::try_from(b"glory to Ukraine".as_slice()).expect("static length")), // sensitive_data,
        None, // outside_info,
        None, // creation_pcrs,
    )
}
