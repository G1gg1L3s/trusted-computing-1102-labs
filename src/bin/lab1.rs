use std::str::FromStr;

use anyhow::Context;
use tss_esapi::TctiNameConf;

fn main() -> anyhow::Result<()> {
    let tcti = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("provide TCTI as a first arg"))?;

    let conf = TctiNameConf::from_str(&tcti).context("failed to parse TCTI")?;
    let mut ctx = tss_esapi::Context::new(conf).context("failed to open context")?;

    ctx.startup(tss_esapi::constants::StartupType::Clear)
        .context("failed to startup")?;

    let buff = ctx.get_random(32).context("failed to get random")?;
    let bytes = buff.as_slice();

    println!("{:?}", bytes);

    Ok(())
}
