use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, error::Error, time::SystemTime};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    process(&MOZILLA_PROD).await
}

async fn process(source: &Source) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("rustls-crlite/backend")
        .build()
        .expect("Failed to create HTTP client");

    let response = client
        .get(source.records_url)
        .send()
        .await
        .map_err(|e| format!("Records request failed: {:?}", e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }

    let moz_manifest = response
        .json::<mozilla::Manifest>()
        .await
        .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;

    let by_parent: HashMap<String, mozilla::Item> = HashMap::from_iter(
        moz_manifest
            .data
            .iter()
            .filter_map(|it| Some((it.parent.as_ref()?.clone(), it.clone()))),
    );

    // Walk the DAG of filters, starting from the root full filter.
    let mut next = moz_manifest.data.iter().find(|it| {
        !it.incremental && it.parent.is_none() && it.channel == mozilla::Channel::Default
    });

    let mut download_plan = Vec::new();

    while next.is_some() {
        let item = next.unwrap();
        next = by_parent.get(&item.id);
        download_plan.push(item);
    }

    let mut manifest = Manifest {
        generated_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        comment: "hello world".into(),
        warning: None,
        error: None,
        filters: vec![],
    };

    for p in download_plan {
        let attachment_url = source.attachment_host.to_string() + &p.attachment.location;
        let response = client
            .get(&attachment_url)
            .send()
            .await
            .map_err(|e| format!("Download request failed: {:?}", e))?;
        let bytes = response.bytes().await?;

        // check hash matches
        let actual_hash = Sha256::digest(&bytes);
        if p.attachment.hash != actual_hash.as_slice() {
            return Err(
                "item {p:?} downloaded from {attachment_url:?} does not have correct hash".into(),
            );
        }

        std::fs::write(format!("tmp/{}", p.attachment.filename), bytes)?;

        manifest.filters.push(Filter {
            filename: p.attachment.filename.clone(),
            size: p.attachment.size,
            hash: p.attachment.hash.clone(),
        });
    }

    std::fs::write(
        "tmp/meta.json",
        serde_json::to_string(&manifest)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    Ok(())
}

mod mozilla {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct Manifest {
        pub data: Vec<Item>,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct Item {
        pub attachment: Attachment,
        pub channel: Channel,
        #[serde(rename = "effectiveTimestamp")]
        pub effective_timestamp: u64,
        pub id: String,
        pub incremental: bool,
        pub parent: Option<String>,
        pub last_modified: u64,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq)]
    pub enum Channel {
        #[serde(rename = "default")]
        Default,
        #[serde(rename = "compat")]
        Compat,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct Attachment {
        #[serde(with = "hex::serde")]
        pub hash: Vec<u8>,
        pub size: usize,
        pub filename: String,
        pub location: String,
        pub mimetype: String,
    }
}

struct Source {
    records_url: &'static str,
    attachment_host: &'static str,
}

const MOZILLA_PROD: Source = Source {
    records_url: "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/cert-revocations/records",
    attachment_host: "https://firefox-settings-attachments.cdn.mozilla.net/",
};

#[derive(Clone, Debug, Serialize)]
struct Manifest {
    /// When this file was generated.
    ///
    /// UNIX timestamp in seconds.
    generated_at: u64,

    /// Some human-readable text.
    comment: String,

    /// Any fetcher logs/outputs this message, and then continues.
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,

    /// Any fetcher immediately fails, logging/outputting this message.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,

    /// List of filter files.
    filters: Vec<Filter>,
}

#[derive(Clone, Debug, Serialize)]
struct Filter {
    /// Relative filename.
    ///
    /// This is also the suggested local filename.
    filename: String,

    /// File size, indicative.  Allows a fetcher to predict data usage.
    size: usize,

    /// SHA256 hash of file contents.
    #[serde(with = "hex::serde")]
    hash: Vec<u8>,
}
