// Copyright 2022-2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub(super) enum BuilderState {
    New,
    Registered {},
}
