//! Avoid cyclic crate dependencies between [resolver][`uv_resolver`],
//! [installer][`uv_installer`] and [build][`uv_build`] through [`BuildDispatch`]
//! implementing [`BuildContext`].

use std::ffi::{OsStr, OsString};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use futures::FutureExt;
use itertools::Itertools;
use rustc_hash::FxHashMap;
use tracing::{debug, instrument};

use distribution_types::{CachedDist, IndexLocations, Name, Resolution, SourceDist};
use pypi_types::Requirement;
use uv_build::{SourceBuild, SourceBuildContext};
use uv_cache::Cache;
use uv_client::RegistryClient;
use uv_configuration::{
    BuildKind, BuildOptions, ConfigSettings, Constraints, IndexStrategy, Reinstall, SourceStrategy,
};
use uv_configuration::{BuildOutput, Concurrency};
use uv_distribution::DistributionDatabase;
use uv_git::GitResolver;
use uv_installer::{Installer, Plan, Planner, Preparer, SitePackages};
use uv_python::{Interpreter, PythonEnvironment};
use uv_resolver::{
    ExcludeNewer, FlatIndex, InMemoryIndex, Manifest, OptionsBuilder, PythonRequirement, Resolver,
    ResolverMarkers,
};
use uv_types::{BuildContext, BuildIsolation, EmptyInstalledPackages, HashStrategy, InFlight};

/// The main implementation of [`BuildContext`], used by the CLI, see [`BuildContext`]
/// documentation.
pub struct BuildDispatch<'a> {
    client: &'a RegistryClient,
    cache: &'a Cache,
    constraints: Constraints,
    interpreter: &'a Interpreter,
    index_locations: &'a IndexLocations,
    index_strategy: IndexStrategy,
    flat_index: &'a FlatIndex,
    index: &'a InMemoryIndex,
    git: &'a GitResolver,
    in_flight: &'a InFlight,
    build_isolation: BuildIsolation<'a>,
    link_mode: install_wheel_rs::linker::LinkMode,
    build_options: &'a BuildOptions,
    config_settings: &'a ConfigSettings,
    hasher: &'a HashStrategy,
    exclude_newer: Option<ExcludeNewer>,
    source_build_context: SourceBuildContext,
    build_extra_env_vars: FxHashMap<OsString, OsString>,
    sources: SourceStrategy,
    concurrency: Concurrency,
}

impl<'a> BuildDispatch<'a> {
    pub fn new(
        client: &'a RegistryClient,
        cache: &'a Cache,
        constraints: Constraints,
        interpreter: &'a Interpreter,
        index_locations: &'a IndexLocations,
        flat_index: &'a FlatIndex,
        index: &'a InMemoryIndex,
        git: &'a GitResolver,
        in_flight: &'a InFlight,
        index_strategy: IndexStrategy,
        config_settings: &'a ConfigSettings,
        build_isolation: BuildIsolation<'a>,
        link_mode: install_wheel_rs::linker::LinkMode,
        build_options: &'a BuildOptions,
        hasher: &'a HashStrategy,
        exclude_newer: Option<ExcludeNewer>,
        sources: SourceStrategy,
        concurrency: Concurrency,
    ) -> Self {
        Self {
            client,
            cache,
            constraints,
            interpreter,
            index_locations,
            flat_index,
            index,
            git,
            in_flight,
            index_strategy,
            config_settings,
            build_isolation,
            link_mode,
            build_options,
            hasher,
            exclude_newer,
            source_build_context: SourceBuildContext::default(),
            build_extra_env_vars: FxHashMap::default(),
            sources,
            concurrency,
        }
    }

    /// Set the environment variables to be used when building a source distribution.
    #[must_use]
    pub fn with_build_extra_env_vars<I, K, V>(mut self, sdist_build_env_variables: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.build_extra_env_vars = sdist_build_env_variables
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        self
    }
}

impl<'a> BuildContext for BuildDispatch<'a> {
    type SourceDistBuilder = SourceBuild;

    fn cache(&self) -> &Cache {
        self.cache
    }

    fn git(&self) -> &GitResolver {
        self.git
    }

    fn build_options(&self) -> &BuildOptions {
        self.build_options
    }

    fn sources(&self) -> SourceStrategy {
        self.sources
    }

    fn index_locations(&self) -> &IndexLocations {
        self.index_locations
    }

    async fn resolve<'data>(&'data self, requirements: &'data [Requirement]) -> Result<Resolution> {
        let python_requirement = PythonRequirement::from_interpreter(self.interpreter);
        let markers = self.interpreter.resolver_markers();
        let tags = self.interpreter.tags()?;

        let resolver = Resolver::new(
            Manifest::simple(requirements.to_vec()).with_constraints(self.constraints.clone()),
            OptionsBuilder::new()
                .exclude_newer(self.exclude_newer)
                .index_strategy(self.index_strategy)
                .build(),
            &python_requirement,
            ResolverMarkers::specific_environment(markers),
            Some(tags),
            self.flat_index,
            self.index,
            self.hasher,
            self,
            EmptyInstalledPackages,
            DistributionDatabase::new(self.client, self, self.concurrency.downloads),
        )?;
        let graph = resolver.resolve().await.with_context(|| {
            format!(
                "No solution found when resolving: {}",
                requirements.iter().map(ToString::to_string).join(", "),
            )
        })?;
        Ok(Resolution::from(graph))
    }

    #[instrument(
        skip(self, resolution, venv),
        fields(
            resolution = resolution.distributions().map(ToString::to_string).join(", "),
            venv = ?venv.root()
        )
    )]
    async fn install<'data>(
        &'data self,
        resolution: &'data Resolution,
        venv: &'data PythonEnvironment,
    ) -> Result<Vec<CachedDist>> {
        debug!(
            "Installing in {} in {}",
            resolution
                .distributions()
                .map(ToString::to_string)
                .join(", "),
            venv.root().display(),
        );

        // Determine the current environment markers.
        let tags = self.interpreter.tags()?;
        let markers = self.interpreter.resolver_markers();

        // Determine the set of installed packages.
        let site_packages = SitePackages::from_environment(venv)?;

        let requirements = resolution.requirements().collect::<Vec<_>>();

        let Plan {
            cached,
            remote,
            reinstalls,
            extraneous: _,
        } = Planner::new(&requirements).build(
            site_packages,
            &Reinstall::default(),
            &BuildOptions::default(),
            self.hasher,
            self.index_locations,
            self.cache(),
            venv,
            &markers,
            tags,
        )?;

        // Nothing to do.
        if remote.is_empty() && cached.is_empty() && reinstalls.is_empty() {
            debug!("No build requirements to install for build");
            return Ok(vec![]);
        }

        // Resolve any registry-based requirements.
        let remote = remote
            .iter()
            .map(|dist| {
                resolution
                    .get_remote(&dist.name)
                    .cloned()
                    .expect("Resolution should contain all packages")
            })
            .collect::<Vec<_>>();

        // Download any missing distributions.
        let wheels = if remote.is_empty() {
            vec![]
        } else {
            // TODO(konstin): Check that there is no endless recursion.
            let preparer = Preparer::new(
                self.cache,
                tags,
                self.hasher,
                self.build_options,
                DistributionDatabase::new(self.client, self, self.concurrency.downloads),
            );

            debug!(
                "Downloading and building requirement{} for build: {}",
                if remote.len() == 1 { "" } else { "s" },
                remote.iter().map(ToString::to_string).join(", ")
            );

            preparer
                .prepare(remote, self.in_flight)
                .await
                .context("Failed to prepare distributions")?
        };

        // Remove any unnecessary packages.
        if !reinstalls.is_empty() {
            for dist_info in &reinstalls {
                let summary = uv_installer::uninstall(dist_info)
                    .await
                    .context("Failed to uninstall build dependencies")?;
                debug!(
                    "Uninstalled {} ({} file{}, {} director{})",
                    dist_info.name(),
                    summary.file_count,
                    if summary.file_count == 1 { "" } else { "s" },
                    summary.dir_count,
                    if summary.dir_count == 1 { "y" } else { "ies" },
                );
            }
        }

        // Install the resolved distributions.
        let mut wheels = wheels.into_iter().chain(cached).collect::<Vec<_>>();
        if !wheels.is_empty() {
            debug!(
                "Installing build requirement{}: {}",
                if wheels.len() == 1 { "" } else { "s" },
                wheels.iter().map(ToString::to_string).join(", ")
            );
            wheels = Installer::new(venv)
                .with_link_mode(self.link_mode)
                .with_cache(self.cache)
                .install(wheels)
                .await
                .context("Failed to install build dependencies")?;
        }

        Ok(wheels)
    }

    #[instrument(skip_all, fields(version_id = version_id, subdirectory = ?subdirectory))]
    async fn setup_build<'data>(
        &'data self,
        source: &'data Path,
        subdirectory: Option<&'data Path>,
        version_id: &'data str,
        dist: Option<&'data SourceDist>,
        build_kind: BuildKind,
        build_output: BuildOutput,
    ) -> Result<SourceBuild> {
        let dist_name = dist.map(distribution_types::Name::name);
        // Note we can only prevent builds by name for packages with names
        // unless all builds are disabled.
        if self
            .build_options
            .no_build_requirement(dist_name)
            // We always allow editable builds
            && !matches!(build_kind, BuildKind::Editable)
        {
            if let Some(dist) = dist {
                return Err(anyhow!(
                    "Building source distributions for {} is disabled",
                    dist.name()
                ));
            }
            return Err(anyhow!("Building source distributions is disabled"));
        }

        let builder = SourceBuild::setup(
            source,
            subdirectory,
            dist_name,
            self.interpreter,
            self,
            self.source_build_context.clone(),
            version_id.to_string(),
            self.config_settings.clone(),
            self.build_isolation,
            build_kind,
            self.build_extra_env_vars.clone(),
            build_output,
            self.concurrency.builds,
        )
        .boxed_local()
        .await?;
        Ok(builder)
    }
}
