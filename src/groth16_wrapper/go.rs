use std::{cmp::Ordering, process::Command};
use regex::Regex;
use anyhow::{anyhow, Result};

const MIN_VERSION: &str = "go1.19.0";

pub fn verify_go() -> bool {
    let min_version = GoVersion::parse(MIN_VERSION).unwrap();
    match go_version() {
        Ok(current_version) => {
            match current_version.cmp(&min_version) {
                Ordering::Greater | Ordering::Equal => {
                    log::info!("Found Go installation");
                    true
                }
                Ordering::Less => {
                    log::error!("Go installation is less than {}", MIN_VERSION);
                    false
                }
            }
        },
        Err(_) => {
            log::error!("Could not find Go installation. Make sure Go is installed [{}+]", MIN_VERSION);
            false
        },
    }
}

pub fn go_build(project_path: &str) -> bool {
    match Command::new("go").args(&["build", "-C", project_path]).output() {
        Ok(output) if output.status.success() => {
            log::info!("Go built successfully [{}]", project_path);
            true
        }
        Ok(output) => {
            log::error!("Failed to compile Go code [{}]: {}", project_path, String::from_utf8_lossy(&output.stderr));
            false
        }
        Err(e) => {
            log::error!("Failed to compile Go code [{}]: {}", project_path, e);
            false
        }
    }
}

fn go_version() -> Result<GoVersion> {
    let output = Command::new("go").args(&["version"]).output();
    match output {
        Ok(output) => {
            let version_string = String::from_utf8_lossy(&output.stdout);
            match GoVersion::parse(&version_string) {
                Some(version) => Ok(version),
                None => Err(anyhow!("Failed to parse Go version")),
            }
        },
        Err(e) => Err(anyhow!("{}", e)),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GoVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl GoVersion {
    // Parses a version string like "go1.22.3" into GoVersion struct
    fn parse(version: &str) -> Option<Self> {
        let re = Regex::new(r"go(\d+)\.(\d+)\.(\d+)").ok()?;
        let caps = re.captures(version)?;

        Some(GoVersion {
            major: caps[1].parse().ok()?,
            minor: caps[2].parse().ok()?,
            patch: caps[3].parse().ok()?,
        })
    }

    // Compares this version to another GoVersion
    fn cmp(&self, other: &Self) -> Ordering {
        self.major.cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}
