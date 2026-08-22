// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Independent traffic classes for admission and device scheduling.
//!
//! Client, replication, reconstruction, and auditor work must not share a
//! catch-all FIFO budget (AGENTS.md L8, §12). Unknown traffic is rejected,
//! not folded into another class.

use std::fmt;

/// Work class with its own admission budget.
///
/// There is no `Other` / default variant: a request that cannot name one of
/// these four classes is not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficClass {
    /// Client-facing account / container / object / proxy requests.
    Foreground,
    /// Replica / SSYNC / handoff traffic.
    Replication,
    /// Erasure-code reconstruction.
    Reconstruction,
    /// Auditor and other maintenance scans.
    Auditor,
}

impl TrafficClass {
    /// Every class, in stable slot order. Length is the number of independent
    /// class budgets; there is no fifth FIFO catch-all.
    pub const ALL: [TrafficClass; 4] = [
        TrafficClass::Foreground,
        TrafficClass::Replication,
        TrafficClass::Reconstruction,
        TrafficClass::Auditor,
    ];

    /// Index into a per-class `[T; 4]` (same order as [`Self::ALL`]).
    pub const fn index(self) -> usize {
        match self {
            TrafficClass::Foreground => 0,
            TrafficClass::Replication => 1,
            TrafficClass::Reconstruction => 2,
            TrafficClass::Auditor => 3,
        }
    }

    /// Inverse of [`Self::index`]. Out-of-range is `None`, not a FIFO class.
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(TrafficClass::Foreground),
            1 => Some(TrafficClass::Replication),
            2 => Some(TrafficClass::Reconstruction),
            3 => Some(TrafficClass::Auditor),
            _ => None,
        }
    }

    /// Wire / metric name. Unknown strings must not map here (see [`Self::parse`]).
    pub const fn as_str(self) -> &'static str {
        match self {
            TrafficClass::Foreground => "foreground",
            TrafficClass::Replication => "replication",
            TrafficClass::Reconstruction => "reconstruction",
            TrafficClass::Auditor => "auditor",
        }
    }

    /// Parse a class name. Unrecognized input is `None` (fail closed).
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "foreground" | "Foreground" => Some(TrafficClass::Foreground),
            "replication" | "Replication" => Some(TrafficClass::Replication),
            "reconstruction" | "Reconstruction" => Some(TrafficClass::Reconstruction),
            "auditor" | "Auditor" => Some(TrafficClass::Auditor),
            _ => None,
        }
    }
}

impl fmt::Display for TrafficClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_named_classes_no_catch_all() {
        assert_eq!(TrafficClass::ALL.len(), 4);
        assert_eq!(TrafficClass::from_index(4), None);
        assert_eq!(TrafficClass::from_index(usize::MAX), None);
        assert_eq!(TrafficClass::parse("other"), None);
        assert_eq!(TrafficClass::parse("fifo"), None);
        assert_eq!(TrafficClass::parse(""), None);
        for (i, class) in TrafficClass::ALL.iter().copied().enumerate() {
            assert_eq!(class.index(), i);
            assert_eq!(TrafficClass::from_index(i), Some(class));
            assert_eq!(TrafficClass::parse(class.as_str()), Some(class));
        }
    }

    #[test]
    fn exhaustive_match_has_no_wildcard_arm() {
        fn label(class: TrafficClass) -> &'static str {
            match class {
                TrafficClass::Foreground => "foreground",
                TrafficClass::Replication => "replication",
                TrafficClass::Reconstruction => "reconstruction",
                TrafficClass::Auditor => "auditor",
            }
        }
        for class in TrafficClass::ALL {
            assert_eq!(label(class), class.as_str());
        }
    }
}
