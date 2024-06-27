use std::borrow::Cow;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use itertools::Either;
use uv_cache::Cache;
use uv_fs::{LockedFile, Simplified};

use crate::discovery::find_toolchain;
use crate::toolchain::Toolchain;
use crate::virtualenv::{virtualenv_python_executable, PyVenvConfiguration};
use crate::ImplementationName;
use crate::VersionRequest;
use crate::{
    EnvironmentPreference, Error, Interpreter, Prefix, Target, ToolchainNotFound,
    ToolchainPreference, ToolchainRequest,
};

/// A Python environment, consisting of a Python [`Interpreter`] and its associated paths.
#[derive(Debug, Clone)]
pub struct PythonEnvironment(Arc<PythonEnvironmentShared>);

#[derive(Debug, Clone)]
struct PythonEnvironmentShared {
    root: PathBuf,
    interpreter: Interpreter,
}

/// The result of failed toolchain discovery.
///
/// See [`InterpreterResult`].
#[derive(Clone, Debug, Error)]
pub enum EnvironmentNotFound {
    /// No Python environments were found.
    None(EnvironmentPreference, Option<VersionRequest>),
    /// No Python environments with the requested version were found.
    NoMatchingVersion(EnvironmentPreference, VersionRequest),
    /// No Python environments with the requested implementation name were found.
    NoMatchingImplementation(EnvironmentPreference, ImplementationName),
    /// No Python environments with the requested implementation name and version were found.
    NoMatchingImplementationVersion(EnvironmentPreference, ImplementationName, VersionRequest),
}

impl EnvironmentNotFound {
    fn try_from(value: ToolchainNotFound) -> Either<Self, ToolchainNotFound> {
        match value {
            ToolchainNotFound::NoPythonInstallation(_, preference, version_request) => {
                Either::Left(Self::None(preference, version_request))
            }
            ToolchainNotFound::NoMatchingVersion(_, preference, version_request) => {
                Either::Left(Self::NoMatchingVersion(preference, version_request))
            }
            ToolchainNotFound::NoMatchingImplementation(_, preference, implementation) => {
                Either::Left(Self::NoMatchingImplementation(preference, implementation))
            }
            ToolchainNotFound::NoMatchingImplementationVersion(
                _,
                preference,
                implementation,
                version,
            ) => Either::Left(Self::NoMatchingImplementationVersion(
                preference,
                implementation,
                version,
            )),
            _ => Either::Right(value),
        }
    }

    fn preference(&self) -> EnvironmentPreference {
        match self {
            Self::None(preference, _)
            | Self::NoMatchingVersion(preference, _)
            | Self::NoMatchingImplementation(preference, _)
            | Self::NoMatchingImplementationVersion(preference, _, _) => *preference,
        }
    }
}

impl fmt::Display for EnvironmentNotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let environment = match self.preference() {
            EnvironmentPreference::Any => "virtual or system environment",
            EnvironmentPreference::ExplicitSystem => "virtual or system environment",
            EnvironmentPreference::OnlySystem => "system environment",
            EnvironmentPreference::OnlyVirtual => "virtual environment",
        };
        match self {
            Self::None(_, None | Some(VersionRequest::Any)) => {
                write!(f, "No {environment} found")
            }
            Self::None(_, Some(version)) | Self::NoMatchingVersion(_, version) => {
                write!(f, "No {environment} found with Python {version}")
            }
            Self::NoMatchingImplementation(_, implementation) => {
                write!(f, "No {environment} found for {}", implementation.pretty())
            }
            Self::NoMatchingImplementationVersion(_, implementation, version) => {
                write!(
                    f,
                    "No {environment} found for {} {version}",
                    implementation.pretty()
                )
            }
        }
    }
}

impl PythonEnvironment {
    /// Find a [`PythonEnvironment`] matching the given request and preference.
    ///
    /// If looking for a Python toolchain to create a new environment, use [`Toolchain::find`]
    /// instead.
    pub fn find(
        request: &ToolchainRequest,
        preference: EnvironmentPreference,
        cache: &Cache,
    ) -> Result<Self, Error> {
        let toolchain = match find_toolchain(
            request,
            preference,
            // Ignore managed toolchains when looking for environments
            ToolchainPreference::OnlySystem,
            cache,
        )? {
            Ok(toolchain) => toolchain,
            Err(err) => match EnvironmentNotFound::try_from(err) {
                Either::Left(err) => return Err(Error::MissingEnvironment(err)),
                // We generally shouldn't hit this case when looking for environments
                Either::Right(err) => return Err(Error::MissingToolchain(err)),
            },
        };
        Ok(Self::from_toolchain(toolchain))
    }

    /// Create a [`PythonEnvironment`] from the virtual environment at the given root.
    pub fn from_root(root: impl AsRef<Path>, cache: &Cache) -> Result<Self, Error> {
        let venv = match fs_err::canonicalize(root.as_ref()) {
            Ok(venv) => venv,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::MissingToolchain(
                    crate::ToolchainNotFound::DirectoryNotFound(root.as_ref().to_path_buf()),
                ));
            }
            Err(err) => return Err(Error::Discovery(err.into())),
        };
        let executable = virtualenv_python_executable(venv);
        let interpreter = Interpreter::query(executable, cache)?;

        Ok(Self(Arc::new(PythonEnvironmentShared {
            root: interpreter.sys_prefix().to_path_buf(),
            interpreter,
        })))
    }

    /// Create a [`PythonEnvironment`] from an existing [`Toolchain`].
    pub fn from_toolchain(toolchain: Toolchain) -> Self {
        Self::from_interpreter(toolchain.into_interpreter())
    }

    /// Create a [`PythonEnvironment`] from an existing [`Interpreter`].
    pub fn from_interpreter(interpreter: Interpreter) -> Self {
        Self(Arc::new(PythonEnvironmentShared {
            root: interpreter.sys_prefix().to_path_buf(),
            interpreter,
        }))
    }

    /// Create a [`PythonEnvironment`] from an existing [`Interpreter`] and `--target` directory.
    #[must_use]
    pub fn with_target(self, target: Target) -> Self {
        let inner = Arc::unwrap_or_clone(self.0);
        Self(Arc::new(PythonEnvironmentShared {
            interpreter: inner.interpreter.with_target(target),
            ..inner
        }))
    }

    /// Create a [`PythonEnvironment`] from an existing [`Interpreter`] and `--prefix` directory.
    #[must_use]
    pub fn with_prefix(self, prefix: Prefix) -> Self {
        let inner = Arc::unwrap_or_clone(self.0);
        Self(Arc::new(PythonEnvironmentShared {
            interpreter: inner.interpreter.with_prefix(prefix),
            ..inner
        }))
    }

    /// Returns the root (i.e., `prefix`) of the Python interpreter.
    pub fn root(&self) -> &Path {
        &self.0.root
    }

    /// Return the [`Interpreter`] for this virtual environment.
    ///
    /// See also [`PythonEnvironment::into_interpreter`].
    pub fn interpreter(&self) -> &Interpreter {
        &self.0.interpreter
    }

    /// Return the [`PyVenvConfiguration`] for this environment, as extracted from the
    /// `pyvenv.cfg` file.
    pub fn cfg(&self) -> Result<PyVenvConfiguration, Error> {
        Ok(PyVenvConfiguration::parse(self.0.root.join("pyvenv.cfg"))?)
    }

    /// Returns the location of the Python executable.
    pub fn python_executable(&self) -> &Path {
        self.0.interpreter.sys_executable()
    }

    /// Returns an iterator over the `site-packages` directories inside the environment.
    ///
    /// In most cases, `purelib` and `platlib` will be the same, and so the iterator will contain
    /// a single element; however, in some distributions, they may be different.
    ///
    /// Some distributions also create symbolic links from `purelib` to `platlib`; in such cases, we
    /// still deduplicate the entries, returning a single path.
    pub fn site_packages(&self) -> impl Iterator<Item = Cow<Path>> {
        let target = self.0.interpreter.target().map(Target::site_packages);

        let prefix = self
            .0
            .interpreter
            .prefix()
            .map(|prefix| prefix.site_packages(self.0.interpreter.virtualenv()));

        let interpreter = if target.is_none() && prefix.is_none() {
            Some(self.0.interpreter.site_packages())
        } else {
            None
        };

        target
            .into_iter()
            .flatten()
            .map(Cow::Borrowed)
            .chain(prefix.into_iter().flatten().map(Cow::Owned))
            .chain(interpreter.into_iter().flatten().map(Cow::Borrowed))
    }

    /// Returns the path to the `bin` directory inside this environment.
    pub fn scripts(&self) -> &Path {
        self.0.interpreter.scripts()
    }

    /// Grab a file lock for the environment to prevent concurrent writes across processes.
    pub fn lock(&self) -> Result<LockedFile, std::io::Error> {
        if let Some(target) = self.0.interpreter.target() {
            // If we're installing into a `--target`, use a target-specific lock file.
            LockedFile::acquire(target.root().join(".lock"), target.root().user_display())
        } else if let Some(prefix) = self.0.interpreter.prefix() {
            // Likewise, if we're installing into a `--prefix`, use a prefix-specific lock file.
            LockedFile::acquire(prefix.root().join(".lock"), prefix.root().user_display())
        } else if self.0.interpreter.is_virtualenv() {
            // If the environment a virtualenv, use a virtualenv-specific lock file.
            LockedFile::acquire(self.0.root.join(".lock"), self.0.root.user_display())
        } else {
            // Otherwise, use a global lock file.
            LockedFile::acquire(
                env::temp_dir().join(format!("uv-{}.lock", cache_key::digest(&self.0.root))),
                self.0.root.user_display(),
            )
        }
    }

    /// Return the [`Interpreter`] for this environment.
    ///
    /// See also [`PythonEnvironment::interpreter`].
    pub fn into_interpreter(self) -> Interpreter {
        Arc::unwrap_or_clone(self.0).interpreter
    }
}
