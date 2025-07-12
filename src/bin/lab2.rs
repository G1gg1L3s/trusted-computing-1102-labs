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
    },
    structures::{
        Auth, Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, Public,
        PublicEccParameters, SymmetricDefinitionObject,
    },
};

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

    ctx.execute_with_nullauth_session(|ctx| -> anyhow::Result<()> {
        let primary = ctx
            .create_primary(
                Hierarchy::Owner,
                Public::Ecc {
                    object_attributes: ObjectAttributesBuilder::new()
                        .with_user_with_auth(true)
                        .with_restricted(true)
                        .with_decrypt(true)
                        .with_fixed_tpm(true)
                        .with_fixed_parent(true)
                        .with_sensitive_data_origin(true)
                        .build()
                        .unwrap(),
                    name_hashing_algorithm: HashingAlgorithm::Sha256,
                    auth_policy: Digest::default(),
                    parameters: PublicEccParameters::builder()
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
                        .unwrap(),
                    unique: EccPoint::default(),
                },
                Some(Auth::try_from(b"pass".to_vec()).unwrap()), // auth_value
                None,                                            // initial_data
                None,                                            // outside_info
                None,                                            // creation_pcrs
            )
            .context("failed to crate primary")?;

        println!(">> {:?}", primary.out_public);

        ctx.flush_context(ObjectHandle::from(primary.key_handle))
            .context("failed to flush context")?;

        Ok(())
    })?;

    Ok(())
}
