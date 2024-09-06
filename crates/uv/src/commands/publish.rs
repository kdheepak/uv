use crate::commands::ExitStatus;
use crate::printer::Printer;
use anyhow::{bail, Result};
use owo_colors::OwoColorize;
use std::fmt::Write;
use url::Url;
use uv_client::BaseClientBuilder;
use uv_publish::{files_for_publishing, upload};

const PYPI_UPLOAD_URL: &str = "https://upload.pypi.org/legacy/";

pub(crate) async fn publish(
    paths: Option<Vec<String>>,
    upload_url: Option<Url>,
    username: Option<String>,
    password: Option<String>,
    pep694: bool,
    printer: Printer,
) -> Result<ExitStatus> {
    let files = files_for_publishing(paths)?;
    match files.len() {
        0 => bail!("No files found to publish"),
        1 => writeln!(
            printer.stderr(),
            "{}",
            format!("Publishing {}", "1 file".bold()).dimmed()
        )?,
        n => writeln!(printer.stderr(), "Publishing {} files", n)?,
    }

    // TODO(konsti): Use settings instead.
    let upload_url = upload_url.unwrap_or(Url::parse(PYPI_UPLOAD_URL).unwrap());

    let client = BaseClientBuilder::new().retries(0).build();

    for (file, filename) in files {
        writeln!(
            printer.stderr(),
            "{}",
            format!("Uploading {}", filename.bold()).dimmed()
        )?;
        upload(
            &file,
            &filename,
            &upload_url,
            &client,
            username.as_deref(),
            password.as_deref(),
        )
        .await?;
    }

    Ok(ExitStatus::Success)
}
