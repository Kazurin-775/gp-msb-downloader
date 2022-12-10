use anyhow::Context;
use serde::{Deserialize, Serialize};
use tinytemplate::TinyTemplate;

use crate::config::ApiEntries;

pub fn compile(apis: &ApiEntries) -> anyhow::Result<TinyTemplate<'_>> {
    let mut tt = TinyTemplate::new();
    tt.add_template("today", &apis.today)
        .context("compile 'today'")?;
    tt.add_template("key", &apis.key).context("compile 'key'")?;
    tt.add_template("file", &apis.file)
        .context("compile 'file'")?;
    Ok(tt)
}

pub async fn get_todays_id(
    client: &reqwest::Client,
    apis: &TinyTemplate<'_>,
) -> anyhow::Result<u32> {
    #[derive(Deserialize)]
    struct Resp {
        pub tab_id: u32,
    }

    let url = apis.render("today", &()).context("generate request URL")?;
    let resp = client.get(url).send().await.context("send request")?;
    Ok(resp
        .json::<Resp>()
        .await
        .context("deserialize JSON")?
        .tab_id)
}

pub async fn get_keys(
    client: &reqwest::Client,
    apis: &TinyTemplate<'_>,
    id: u32,
) -> anyhow::Result<String> {
    #[derive(Serialize)]
    struct Params {
        pub id: u32,
    }
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Resp {
        pub id: u32,
        pub masterKey: String,
    }

    let url = apis
        .render("key", &Params { id })
        .context("generate request URL")?;
    let resp = client.get(url).send().await.context("send request")?;
    let content = resp.bytes().await.context("read response")?;
    tokio::fs::write(format!("{}/keys.json", id), &content)
        .await
        .context("write keys")?;
    let resp: Resp = serde_json::from_slice(&content).context("parse JSON")?;
    assert_eq!(resp.id, id);
    Ok(resp.masterKey)
}

pub async fn get_tab_file(
    client: &reqwest::Client,
    apis: &TinyTemplate<'_>,
    id: u32,
    key: &str,
) -> anyhow::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Params<'a> {
        pub id: u32,
        pub key: &'a str,
    }

    let url = apis
        .render("file", &Params { id, key })
        .context("generate request URL")?;
    let resp = client.get(url).send().await.context("send request")?;
    let content = resp.bytes().await.context("read response")?;
    tokio::fs::write(format!("{}/file.bin", id), &content)
        .await
        .context("write original file")?;
    Ok(content.into())
}
