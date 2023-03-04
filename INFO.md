## gp-msb-downloader

This is an unofficial client to a proprietary secure file sharing protocol. This application can be used to download files from servers running such protocol.

This repo is (intentially) left incomplete; some proprietary data is excluded from the source code. To run this application, some additional configuration files are required:

- `config/config.toml`
- `config/dh-prime-p.bin`

An example of `config/config.toml` is shown below, with some sensitive parts removed. To obtain these sensitive parts, you may need to examine a file named `G*****P***.exe` (as well as generate a private key for yourself manually).

```toml
priv_key = "73FF*******..."
ua = "G*****P**/*.*.*.** (W****** ** **.*)"

[api]
today = "***"
key = "***"
file = "***"
```
