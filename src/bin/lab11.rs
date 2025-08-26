use std::str::FromStr;

use anyhow::Context;
use base16ct::HexDisplay;
use sha2::Digest as _;
use tss_esapi::{
    TctiNameConf,
    handles::{ObjectHandle, PcrHandle},
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::{Auth, Digest, DigestValues, PcrSelectionList, PcrSlot},
};

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let tcti = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "device:/dev/tpmrm0".to_string());

    let conf = TctiNameConf::from_str(&tcti).context("failed to parse TCTI")?;
    let mut ctx = tss_esapi::Context::new(conf).context("failed to open context")?;

    ctx.startup(tss_esapi::constants::StartupType::Clear)
        .context("failed to startup")?;

    ctx.tr_set_auth(ObjectHandle::Owner, Auth::try_from(b"".to_vec()).unwrap())
        .context("failed to set auth")?;

    ctx.execute_with_session(None, |ctx| -> anyhow::Result<()> {
        let (update_counter, pcr_selection, digest) = read_pcr(ctx, PcrSlot::Slot23)?;

        println!(">> update_counter: {update_counter}");
        println!(">> pcr_selection: {:?}", pcr_selection.selected());
        println!(">> digest: {}", HexDisplay(digest.as_slice()));

        if digest.as_slice().iter().any(|b| *b != 0x00) {
            ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.pcr_reset(PcrHandle::Pcr23)
                    .context("failed to reset pcr23")
            })?;
        }

        let content = std::fs::read("/etc/passwd").context("failed to read /etc/passwd")?;
        let passwd_hash = sha2::Sha256::digest(&content);
        let mut digest = DigestValues::new();
        digest.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(&passwd_hash[..]).context("failed to convert hash to Digest")?,
        );

        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.pcr_extend(PcrHandle::Pcr23, digest)
                .context("failed to extend pcr")
        })?;

        println!(">> Extended with {}", HexDisplay(&passwd_hash));

        let (update_counter, pcr_selection, digest) = read_pcr(ctx, PcrSlot::Slot23)?;

        println!(">> update_counter: {update_counter}");
        println!(">> pcr_selection: {:?}", pcr_selection.selected());
        println!(">> digest: {}", HexDisplay(digest.as_slice()));

        let expected_digest = {
            let mut hasher = sha2::Sha256::new_with_prefix([0; 32]);
            hasher.update(passwd_hash);
            hasher.finalize()
        };

        println!(">> expected digest: {}", HexDisplay(&expected_digest));

        Ok(())
    })?;

    Ok(())
}

fn read_pcr(
    ctx: &mut tss_esapi::Context,
    slot: PcrSlot,
) -> Result<(u32, tss_esapi::structures::PcrSelection, Digest), anyhow::Error> {
    let (update_counter, pcr_selection, digests) = ctx
        .pcr_read(
            PcrSelectionList::builder()
                .with_selection(HashingAlgorithm::Sha256, &[slot])
                .build()
                .expect("valid selection"),
        )
        .context("failed to read pcr selection")?;
    let [pcr_selection] = pcr_selection.get_selections() else {
        anyhow::bail!("multiple pcr selections returned: {:?}", pcr_selection);
    };
    let [digest] = digests.value() else {
        anyhow::bail!("multiple digests returned: {:?}", digests);
    };
    Ok((update_counter, pcr_selection.to_owned(), digest.to_owned()))
}
