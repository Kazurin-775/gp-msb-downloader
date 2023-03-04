mod api;
mod config;

use std::path::PathBuf;

use anyhow::Context;
use openssl::{bn::BigNum, dh::Dh, symm::Cipher};
use rand::Rng;

const DH_P: &[u8; 128] = include_bytes!("../config/dh-prime-p.bin");
const DH_G: &[u8; 1] = &[2];

fn dh_generate_key(config: &config::Config) -> anyhow::Result<Dh<openssl::pkey::Private>> {
    let dh_p = BigNum::from_slice(DH_P).unwrap();
    let dh_g = BigNum::from_slice(DH_G).unwrap();
    let dh = Dh::from_pqg(dh_p, None, dh_g).unwrap();
    let dh = dh
        .set_private_key(BigNum::from_hex_str(&config.priv_key).unwrap())
        .unwrap();
    // let dh = dh.generate_key().context("DHKE generate key")?;
    Ok(dh)
}

async fn api_fetch_tod(
    config: &config::Config,
    apis: &tinytemplate::TinyTemplate<'_>,
    cli_pubkey: &str,
) -> anyhow::Result<(u32, String, Vec<u8>)> {
    let client = reqwest::Client::builder()
        .user_agent(&config.ua)
        .build()
        .context("build HTTP client")?;

    let id = api::get_todays_id(&client, apis)
        .await
        .context("get today's ID")?;
    log::info!("Today's tab ID = {}", id);

    let working_dir = PathBuf::from(id.to_string());
    if working_dir
        .try_exists()
        .context("check working directory")?
    {
        anyhow::bail!("directory {} already exists, delete it first", id);
    }
    tokio::fs::create_dir(&working_dir)
        .await
        .context("create working directory")?;

    if !config.no_delay {
        let rest_millis = rand::thread_rng().gen_range(5_000..=30_000);
        log::info!("Waiting for {} ms before continuing", rest_millis);
        tokio::time::sleep(std::time::Duration::from_millis(rest_millis)).await;
    }

    log::info!("Obtaining keys");
    let phase2_key = api::get_keys(&client, apis, id)
        .await
        .context("get phase 2 keys")?;
    log::debug!("Phase 2 key = {}", phase2_key);

    log::info!("Downloading encrypted file");
    let data = api::get_tab_file(&client, apis, id, cli_pubkey)
        .await
        .context("download encrypted file")?;

    Ok((id, phase2_key, data))
}

fn phase_1_decrypt(data: &[u8], dh: &Dh<openssl::pkey::Private>) -> anyhow::Result<Vec<u8>> {
    log::info!("Running phase 1 decryption");

    let svr_keysize = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    let (svr_key, rem) = data[5..].split_at(svr_keysize);
    let (iv, rem) = rem.split_at(16);
    let (dec_data_len_loss, enc_data) = (rem[0], &rem[1..]);
    let enc_data_len = enc_data.len();
    let dec_data_len = enc_data_len - dec_data_len_loss as usize;

    log::debug!("Server DH key size = {}", svr_keysize);
    log::debug!("Phase 1 encrypted data length = {}", enc_data_len);
    log::debug!("Phase 1 decrypted data length = {}", dec_data_len);

    let svr_key = BigNum::from_slice(svr_key).context("read server DH key")?;
    let dh_shared_key = dh.compute_key(&svr_key).context("DH compute shared key")?;

    let decrypted = openssl::symm::decrypt(
        Cipher::aes_256_cbc(),
        &dh_shared_key[..256 / 8],
        Some(iv),
        enc_data,
    )
    .context("decrypt (phase 1)")?;
    assert_eq!(decrypted.len(), dec_data_len);

    Ok(decrypted)
}

fn phase_2_decrypt(dec1: &[u8], phase2_key: &str) -> anyhow::Result<Vec<u8>> {
    log::info!("Running phase 2 decryption");

    let mut key2_bytes = [0; 32];
    hex::decode_to_slice(phase2_key, &mut key2_bytes[0..16]).context("parse phase 2 key")?;

    let dec2 = openssl::symm::decrypt(Cipher::aes_256_cbc(), &key2_bytes, Some(&[0; 16]), dec1)
        .context("decrypt (phase 2)")?;
    Ok(dec2)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    // Read configuration

    let config = tokio::fs::read_to_string("config/config.toml")
        .await
        .context("read config.toml")?;
    let config: config::Config = toml::from_str(&config).context("parse config.toml")?;
    let apis = api::compile(&config.api).context("compile API templates")?;

    // DHKE initialization

    let dh = dh_generate_key(&config)?;

    let cli_pubkey = dh
        .public_key()
        .to_hex_str()
        .context("public key to hex string")?;
    log::debug!("DHKE public key = {}", cli_pubkey);

    // API requests

    let (id, phase2_key, data) = api_fetch_tod(&config, &apis, &cli_pubkey).await?;

    // Phase 1 decryption

    let dec1 = phase_1_decrypt(&data, &dh)?;

    // Phase 2 decryption

    let dec2 = phase_2_decrypt(&dec1, &phase2_key)?;
    tokio::fs::write(format!("{}/file.gp", id), &dec2)
        .await
        .context("write decrypted file")?;
    log::info!("Successfully saved decrypted tab file to disk");

    Ok(())
}
