use std::str::FromStr;

use anyhow::Context;
use tss_esapi::{
    TctiNameConf,
    constants::SessionType,
    interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
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

    ctx.execute_without_session(|ctx| -> anyhow::Result<()> {
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                tss_esapi::structures::SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .context("failed to start trial session")?
            .ok_or_else(|| anyhow::anyhow!("no auth session returned"))?;

        ctx.policy_password(PolicySession::PolicySession {
            hashing_algorithm: HashingAlgorithm::Sha256,
            session_handle: session.into(),
            session_type: SessionType::Policy,
        })
        .context("failed to execute policy password")?;

        let hash = ctx
            .policy_get_digest(PolicySession::try_from(session).context("expected policy session")?)
            .context("failed to get digest")?;

        println!("{}", base16ct::HexDisplay(&hash));

        Ok(())
    })?;

    Ok(())
}
