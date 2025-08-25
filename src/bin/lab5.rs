use std::str::FromStr;

use anyhow::Context;
use p256::elliptic_curve::sec1::FromEncodedPoint;
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
        Auth, CreatePrimaryKeyResult, Digest, EccParameter, EccPoint, EccScheme,
        KeyDerivationFunctionScheme, Public, PublicEccParameters, SymmetricDefinitionObject,
    },
};

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
        let primary = create_ek_low_p256(ctx)?;
        let Public::Ecc { unique, .. } = primary.out_public else {
            anyhow::bail!(
                "create primary didn't return ecc key: {:?}",
                primary.out_public
            );
        };

        let p256_key = ecc_point_to_p256_key(unique).context("failed to parse ECC key")?;
        println!(">> Ek:\n{}", AsOpensslKey(&p256_key.to_sec1_bytes()));

        ctx.flush_context(ObjectHandle::from(primary.key_handle))
            .context("failed to flush parent context")?;

        Ok(())
    })
}

fn ecc_point_to_p256_key(ecc: EccPoint) -> anyhow::Result<p256::PublicKey> {
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
