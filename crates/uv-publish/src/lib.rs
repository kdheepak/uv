use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use distribution_filename::DistFilename;
use fs_err::File;
use glob::{glob, GlobError, PatternError};
use python_pkginfo::Metadata;
use reqwest::header::AUTHORIZATION;
use reqwest::multipart::Part;
use reqwest::Body;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{fmt, io};
use thiserror::Error;
use url::Url;
use uv_client::BaseClient;
use uv_fs::Simplified;
use uv_metadata::read_metadata_async_seek;

#[derive(Error, Debug)]
pub enum PublishError {
    #[error("Invalid publish paths")]
    Pattern(#[from] PatternError),
    /// [`GlobError`] is a wrapped io error.
    #[error(transparent)]
    Glob(#[from] GlobError),
    #[error("Path patterns didn't match any wheels or source distributions")]
    NoFiles,
    #[error(transparent)]
    Fmt(#[from] fmt::Error),
    #[error("Failed to publish: `{}`", _0.user_display())]
    PublishFile(PathBuf, #[source] PublishFileError),
}

/// Failed to publish a specific file.
///
/// Proxy over [`PublishError`] to attach the path to the error message.
#[derive(Error, Debug)]
pub enum PublishFileError {
    #[error(transparent)]
    PkgInfoError(#[from] python_pkginfo::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Failed to read metadata")]
    Metadata(#[from] uv_metadata::Error),
    #[error("Failed to send POST request: `{0}`")]
    ReqwestMiddleware(Url, #[source] reqwest_middleware::Error),
}

pub fn files_for_publishing(
    paths: Option<Vec<String>>,
) -> Result<Vec<(PathBuf, DistFilename)>, PublishError> {
    let paths = paths.unwrap_or_else(|| vec!["dist/*".to_string()]);
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for path in paths {
        for entry in glob(&path)? {
            let entry = entry?;
            if !seen.insert(entry.clone()) {
                continue;
            }
            if let Some(dist_filename) = entry
                .file_name()
                .and_then(|filename| filename.to_str())
                .and_then(|filename| DistFilename::try_from_normalized_filename(filename))
            {
                files.push((entry, dist_filename));
            }
        }
    }
    Ok(files)
}

/// Calculate the SHA256 of a file.
fn hash_file(path: impl AsRef<Path>) -> Result<String, io::Error> {
    let mut file = File::open(path.as_ref())?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

async fn metadata(file: &Path, filename: &DistFilename) -> Result<Metadata, PublishFileError> {
    match filename {
        DistFilename::SourceDistFilename(_source_dist) => {
            todo!()
        }
        DistFilename::WheelFilename(wheel) => {
            let file = fs_err::tokio::File::open(&file).await?;
            let reader = tokio::io::BufReader::new(file);
            let contents = read_metadata_async_seek(&wheel, reader).await?;
            Ok(python_pkginfo::Metadata::parse(&contents)?)
        }
    }
}

/// Upload a file to a registry.
pub async fn upload(
    file: &Path,
    filename: &DistFilename,
    registry: &Url,
    client: &BaseClient,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), PublishFileError> {
    let hash_hex = hash_file(file)?;

    let metadata = metadata(file, filename).await?;

    let mut api_metadata = vec![
        (":action", "file_upload".to_string()),
        ("sha256_digest", hash_hex),
        ("protocol_version", "1".to_string()),
        ("metadata_version", metadata.metadata_version.clone()),
        // Twine transforms the name with `re.sub("[^A-Za-z0-9.]+", "-", name)`
        // * <https://github.com/pypa/twine/issues/743>
        // * <https://github.com/pypa/twine/blob/5bf3f38ff3d8b2de47b7baa7b652c697d7a64776/twine/package.py#L57-L65>
        // warehouse seems to call `packaging.utils.canonicalize_name` nowadays and has a separate
        // `normalized_name`, so we'll start with this and we'll readjust if there are user reports.
        ("name", metadata.name.clone()),
        ("version", metadata.version.clone()),
        ("filetype", filename.filetype().to_string()),
    ];

    if let DistFilename::WheelFilename(wheel) = filename {
        api_metadata.push(("pyversion", wheel.python_tag.join(".")));
    }

    let mut add_option = |name, value: Option<String>| {
        if let Some(some) = value.clone() {
            api_metadata.push((name, some));
        }
    };

    // https://github.com/pypi/warehouse/blob/d2c36d992cf9168e0518201d998b2707a3ef1e72/warehouse/forklift/legacy.py#L1376-L1430
    add_option("summary", metadata.summary);
    add_option("description", metadata.description);
    add_option(
        "description_content_type",
        metadata.description_content_type,
    );
    add_option("author", metadata.author);
    add_option("author_email", metadata.author_email);
    add_option("maintainer", metadata.maintainer);
    add_option("maintainer_email", metadata.maintainer_email);
    add_option("license", metadata.license);
    add_option("keywords", metadata.keywords);
    add_option("home_page", metadata.home_page);
    add_option("download_url", metadata.download_url);

    // GitLab PyPI repository API implementation requires this metadata field
    // and twine always includes it in the request, even when it's empty.
    api_metadata.push((
        "requires_python",
        metadata.requires_python.unwrap_or("".to_string()),
    ));

    let mut add_vec = |name, values: Vec<String>| {
        for i in values {
            api_metadata.push((name, i.clone()));
        }
    };

    add_vec("classifiers", metadata.classifiers);
    add_vec("platform", metadata.platforms);
    add_vec("requires_dist", metadata.requires_dist);
    add_vec("provides_dist", metadata.provides_dist);
    add_vec("obsoletes_dist", metadata.obsoletes_dist);
    add_vec("requires_external", metadata.requires_external);
    add_vec("project_urls", metadata.project_urls);

    let mut form = reqwest::multipart::Form::new();
    for (key, value) in api_metadata {
        form = form.text(key, value);
    }

    let file: tokio::fs::File = fs_err::tokio::File::open(file).await?.into();
    let file_reader = Body::from(file);
    form = form.part(
        "content",
        Part::stream(file_reader).file_name(filename.to_string()),
    );

    let mut request = client.client().post(registry.clone()).multipart(form);
    if let (Some(username), Some(password)) = (username, password) {
        let credentials = BASE64_STANDARD.encode(format!("{username}:{password}"));
        request = request.header(AUTHORIZATION, format!("Basic {credentials}"));
    }
    let response = request
        .send()
        .await
        .map_err(|err| PublishFileError::ReqwestMiddleware(registry.clone(), err))?;
    println!("{:?}", response);

    if response.status().is_success() {
        return Ok(());
    }

    /*
    let err_text = response.into_string().unwrap_or_else(|e| {
        format!(
            "The registry should return some text, \
            even in case of an error, but didn't ({e})"
        )
    });
    debug!("Upload error response: {}", err_text);
    // Detect FileExistsError the way twine does
    // https://github.com/pypa/twine/blob/87846e5777b380d4704704a69e1f9a7a1231451c/twine/commands/upload.py#L30
    if status == 403 {
        if err_text.contains("overwrite artifact") {
            // Artifactory (https://jfrog.com/artifactory/)
            Err(UploadError::FileExistsError(err_text))
        } else {
            Err(UploadError::AuthenticationError(err_text))
        }
    } else {
        let status_string = status.to_string();
        if status == 409 // conflict, pypiserver (https://pypi.org/project/pypiserver)
            // PyPI / TestPyPI
            || (status == 400 && err_text.contains("already exists"))
            // Nexus Repository OSS (https://www.sonatype.com/nexus-repository-oss)
            || (status == 400 && err_text.contains("updating asset"))
            // # Gitlab Enterprise Edition (https://about.gitlab.com)
            || (status == 400 && err_text.contains("already been taken"))
        {
            Err(UploadError::FileExistsError(err_text))
        } else {
            Err(UploadError::StatusCodeError(status_string, err_text))
        }
    }*/
    todo!()
}
