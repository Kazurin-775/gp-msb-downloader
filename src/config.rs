use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub priv_key: String,
    pub ua: String,
    pub api: ApiEntries,
}

#[derive(Deserialize)]
pub struct ApiEntries {
    pub today: String,
    pub key: String,
    pub file: String,
}
