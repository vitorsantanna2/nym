// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::client::config::Config;
use clap::Args;
use nym_bin_common::version_checker::Version;
use std::fmt::Display;
use std::process;

#[allow(dead_code)]
fn fail_upgrade<D1: Display, D2: Display>(from_version: D1, to_version: D2) -> ! {
    print_failed_upgrade(from_version, to_version);
    process::exit(1)
}

fn print_start_upgrade<D1: Display, D2: Display>(from: D1, to: D2) {
    println!("\n==================\nTrying to upgrade client from {from} to {to} ...");
}

fn print_failed_upgrade<D1: Display, D2: Display>(from: D1, to: D2) {
    eprintln!("Upgrade from {from} to {to} failed!\n==================\n");
}

fn print_successful_upgrade<D1: Display, D2: Display>(from: D1, to: D2) {
    println!("Upgrade from {from} to {to} was successful!\n==================\n");
}

fn outdated_upgrade(config_version: &Version, package_version: &Version) -> ! {
    eprintln!(
        "Cannot perform upgrade from {config_version} to {package_version}. Your version is too old to perform the upgrade.!"
    );
    process::exit(1)
}

fn unsupported_upgrade(current_version: &Version, config_version: &Version) -> ! {
    eprintln!("Cannot perform upgrade from {config_version} to {current_version}. Please let the developers know about this issue if you expected it to work!");
    process::exit(1)
}

fn unimplemented_upgrade(current_version: &Version, config_version: &Version) -> ! {
    eprintln!("Cannot perform upgrade from {config_version} to {current_version} as it hasn't been implemented yet");
    todo!();
    process::exit(1)
}

#[derive(Args, Clone)]
pub(crate) struct Upgrade {
    /// Id of the nym-client we want to upgrade
    #[clap(long)]
    id: String,
}

fn parse_config_version(config: &Config) -> Version {
    let version = Version::parse(&config.base.client.version).unwrap_or_else(|err| {
        eprintln!("failed to parse client version! - {err}");
        process::exit(1)
    });

    if version.is_prerelease() || !version.build.is_empty() {
        eprintln!(
            "Trying to upgrade from a non-released version {version}. This is not supported!"
        );
        process::exit(1)
    }

    version
}

fn parse_package_version() -> Version {
    let version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();

    // technically this is not a correct way of checking it as a released version might contain valid build identifiers
    // however, we are not using them ourselves at the moment and hence it should be fine.
    // if we change our mind, we could easily tweak this code
    if version.is_prerelease() || !version.build.is_empty() {
        eprintln!("Trying to upgrade to a non-released version {version}. This is not supported!");
        process::exit(1)
    }

    version
}

fn do_upgrade(mut config: Config, args: &Upgrade, package_version: &Version) {
    loop {
        let config_version = parse_config_version(&config);

        if &config_version == package_version {
            println!("You're using the most recent version!");
            return;
        }

        config = match config_version.major {
            0 => outdated_upgrade(&config_version, package_version),
            1 => match config_version.minor {
                n if n <= 13 => outdated_upgrade(&config_version, package_version),
                n if n > 13 && n < 19 => unimplemented_upgrade(&config_version, package_version),
                _ => unsupported_upgrade(&config_version, package_version),
            },
            _ => unsupported_upgrade(&config_version, package_version),
        }
    }
}

pub(crate) fn execute(args: &Upgrade) {
    let package_version = parse_package_version();

    let id = &args.id;

    let existing_config = Config::read_from_default_path(id).unwrap_or_else(|err| {
        eprintln!("failed to load existing config file! - {err}");
        process::exit(1)
    });

    if existing_config.base.client.version.is_empty() {
        eprintln!("the existing configuration file does not seem to contain version number.");
        process::exit(1);
    }

    // here be upgrade path to 0.9.X and beyond based on version number from config
    do_upgrade(existing_config, args, &package_version)
}
