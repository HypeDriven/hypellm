//! The checksums the router keeps for artifacts (specification 26.12).
//!
//! A slave reports, for every artifact it holds, the image ID its container
//! runtime computes. That is the slave's word, and this module decides what
//! the router does with it:
//!
//! - **Pinned.** An artifact whose configuration sets `image_id` is held to
//!   that value, always. Nothing a slave reports can move it.
//! - **Learned.** Otherwise the router learns the ID from the first
//!   observation in which a host reports the artifact present *and verified* —
//!   the agent's check that the image carries the registry manifest digest the
//!   administrator configured — and keeps it durably. Learning is refused
//!   while verified hosts disagree, because there is then no one value to
//!   trust.
//! - **Tampered.** A host reporting the artifact under any other ID is holding
//!   something else under the model's name. It is never activated with that
//!   artifact and never used as a copy source; that is enforced by
//!   [`crate::state::FleetSnapshot::artifact_ready`], and this module only
//!   names the hosts so they can be audited and shown.
//!
//! # What a learned checksum is worth
//!
//! Trust on first verified observation. It defends every *later* copy, and
//! every other host, against a slave that serves a different image under the
//! artifact's name. It does not defend against the very first verified
//! reporter lying, because before it there is nothing to compare with. An
//! administrator who wants an anchor independent of every slave pins
//! `image_id` in the configuration. That limit is recorded in
//! `spec/deferred-issues.html`.

use crate::model::{FleetConfig, ImageId};
use crate::state::Inventory;
use hypellm_core::ids::{ArtifactId, HostId};
use std::collections::{BTreeMap, BTreeSet};
use wire_json::{Limits, Object, Value};

/// The most bytes one checksum record may occupy.
pub const MAX_RECORD_BYTES: usize = 1024;

/// One learned checksum, as the durable log holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumRecord {
    /// Which artifact.
    pub artifact: ArtifactId,
    /// The image ID now kept for it.
    pub image_id: ImageId,
    /// The host whose verified observation it was learned from.
    pub host: HostId,
    /// When, in wall-clock milliseconds.
    pub at_millis: u64,
}

/// Encode a checksum record for the log.
#[must_use]
pub fn encode_record(record: &ChecksumRecord) -> Vec<u8> {
    let mut object = Object::new();
    object.push("artifact", Value::from(record.artifact.as_str()));
    object.push("image_id", Value::from(record.image_id.as_str()));
    object.push("host", Value::from(record.host.as_str()));
    object.push(
        "at_millis",
        Value::from(i64::try_from(record.at_millis).unwrap_or(i64::MAX)),
    );
    wire_json::to_vec(&Value::Object(object))
}

/// Decode a checksum record, or `None` if it is not exactly one.
#[must_use]
pub fn decode_record(payload: &[u8]) -> Option<ChecksumRecord> {
    let value = wire_json::parse(
        payload,
        &Limits::SMALL.with_max_input_bytes(MAX_RECORD_BYTES),
    )
    .ok()?;
    Some(ChecksumRecord {
        artifact: ArtifactId::new(value.get("artifact")?.as_str()?).ok()?,
        image_id: ImageId::parse(value.get("image_id")?.as_str()?)?,
        host: HostId::new(value.get("host")?.as_str()?).ok()?,
        at_millis: value.get("at_millis")?.as_u64()?,
    })
}

/// Fold replayed records into the kept set: the first record per artifact
/// wins, so a later frame cannot move an anchor once it is set.
pub fn restore(kept: &mut BTreeMap<ArtifactId, ImageId>, record: ChecksumRecord) {
    kept.entry(record.artifact).or_insert(record.image_id);
}

/// What one observation teaches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Learning {
    /// Checksums to keep from now on, each with the host it came from.
    pub learned: Vec<(ArtifactId, ImageId, HostId)>,
    /// Artifacts whose verified hosts disagree, so nothing was learned.
    pub conflicts: Vec<ArtifactId>,
}

/// What `inventory` teaches, given what is already pinned or kept.
///
/// Only artifacts with neither a pinned nor a kept checksum are considered,
/// and only placements reported present *and* verified with an image ID. One
/// distinct ID across those placements is learned, attributed to the first
/// host (in identifier order) reporting it; more than one is a conflict.
/// Iteration is over ordered maps throughout, so the outcome depends on the
/// inventory and never on hashing.
#[must_use]
pub fn learn(
    config: &FleetConfig,
    kept: &BTreeMap<ArtifactId, ImageId>,
    inventory: &Inventory,
) -> Learning {
    let mut seen: BTreeMap<&ArtifactId, BTreeMap<&ImageId, &HostId>> = BTreeMap::new();
    for ((artifact, host), placement) in &inventory.artifacts {
        let Some(declared) = config.artifacts.get(artifact) else {
            continue;
        };
        if declared.image_id.is_some() || kept.contains_key(artifact) {
            continue;
        }
        if !(placement.present && placement.verified) {
            continue;
        }
        let Some(image) = &placement.image_id else {
            continue;
        };
        seen.entry(artifact)
            .or_default()
            .entry(image)
            .or_insert(host);
    }
    let mut learning = Learning::default();
    for (artifact, ids) in seen {
        let mut ids = ids.into_iter();
        match (ids.next(), ids.next()) {
            (Some((image, host)), None) => {
                learning
                    .learned
                    .push((artifact.clone(), image.clone(), host.clone()));
            }
            (Some(_), Some(_)) => learning.conflicts.push(artifact.clone()),
            _ => {}
        }
    }
    learning
}

/// Every (artifact, host) whose reported image ID differs from the checksum
/// the router holds the artifact to.
#[must_use]
pub fn tampered(
    config: &FleetConfig,
    kept: &BTreeMap<ArtifactId, ImageId>,
    inventory: &Inventory,
) -> BTreeSet<(ArtifactId, HostId)> {
    inventory
        .artifacts
        .iter()
        .filter(|(_, placement)| placement.present)
        .filter_map(|((artifact, host), placement)| {
            let expected = config
                .artifacts
                .get(artifact)
                .and_then(|a| a.image_id.as_ref())
                .or_else(|| kept.get(artifact))?;
            let reported = placement.image_id.as_ref()?;
            (reported != expected).then(|| (artifact.clone(), host.clone()))
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]
mod tests {
    use super::*;
    use crate::model::{Arch, Artifact, ArtifactKind};
    use crate::state::ArtifactPlacement;

    fn image(fill: char) -> ImageId {
        ImageId::parse(&format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn config(pinned: Option<ImageId>) -> FleetConfig {
        let mut fleet = FleetConfig::empty();
        let id = ArtifactId::new("llama").unwrap();
        fleet.artifacts.insert(
            id.clone(),
            Artifact {
                id,
                kind: ArtifactKind::Image,
                arch: Arch::X86_64,
                size_bytes: 1,
                digest: format!("sha256:{}", "0".repeat(64)),
                image_id: pinned,
                source: String::new(),
            },
        );
        fleet
    }

    fn placed(inventory: &mut Inventory, host: &str, verified: bool, id: Option<ImageId>) {
        let artifact = ArtifactId::new("llama").unwrap();
        let host = HostId::new(host).unwrap();
        inventory.artifacts.insert(
            (artifact.clone(), host.clone()),
            ArtifactPlacement {
                artifact,
                host,
                present: true,
                verified,
                bytes_present: 0,
                image_id: id,
            },
        );
    }

    #[test]
    fn a_record_survives_the_log_and_a_malformed_one_is_refused() {
        let record = ChecksumRecord {
            artifact: ArtifactId::new("llama").unwrap(),
            image_id: image('a'),
            host: HostId::new("spark").unwrap(),
            at_millis: 7,
        };
        assert_eq!(decode_record(&encode_record(&record)), Some(record.clone()));
        let text = String::from_utf8(encode_record(&record)).unwrap();
        let upper = text.replace(&"a".repeat(64), &"A".repeat(64));
        assert_eq!(decode_record(upper.as_bytes()), None);
    }

    #[test]
    fn the_first_record_is_the_anchor_and_a_later_one_cannot_move_it() {
        let mut kept = BTreeMap::new();
        let llama = ArtifactId::new("llama").unwrap();
        for fill in ['a', 'b'] {
            restore(
                &mut kept,
                ChecksumRecord {
                    artifact: llama.clone(),
                    image_id: image(fill),
                    host: HostId::new("spark").unwrap(),
                    at_millis: 1,
                },
            );
        }
        assert_eq!(kept.get(&llama), Some(&image('a')));
    }

    #[test]
    fn only_a_verified_unanimous_observation_is_learned() {
        let fleet = config(None);
        let kept = BTreeMap::new();

        // Unverified: the registry-digest check did not pass, so nothing is
        // learned however confident the host's ID looks.
        let mut inventory = Inventory::default();
        placed(&mut inventory, "spark", false, Some(image('a')));
        assert!(learn(&fleet, &kept, &inventory).learned.is_empty());

        // Verified and unanimous.
        placed(&mut inventory, "rig", true, Some(image('a')));
        let learning = learn(&fleet, &kept, &inventory);
        assert_eq!(learning.learned.len(), 1);
        assert_eq!(learning.learned[0].1, image('a'));
        assert_eq!(learning.learned[0].2.as_str(), "rig");

        // Two verified hosts that disagree: nothing to trust.
        placed(&mut inventory, "spark", true, Some(image('b')));
        let learning = learn(&fleet, &kept, &inventory);
        assert!(learning.learned.is_empty());
        assert_eq!(learning.conflicts.len(), 1);
    }

    #[test]
    fn nothing_is_learned_over_a_pinned_or_kept_checksum() {
        let mut inventory = Inventory::default();
        placed(&mut inventory, "spark", true, Some(image('b')));
        assert!(learn(&config(Some(image('a'))), &BTreeMap::new(), &inventory)
            .learned
            .is_empty());
        let mut kept = BTreeMap::new();
        kept.insert(ArtifactId::new("llama").unwrap(), image('a'));
        assert!(learn(&config(None), &kept, &inventory).learned.is_empty());
    }

    #[test]
    fn a_host_reporting_another_image_is_tampered_and_a_matching_one_is_not() {
        let mut inventory = Inventory::default();
        placed(&mut inventory, "honest", true, Some(image('a')));
        placed(&mut inventory, "liar", true, Some(image('b')));
        placed(&mut inventory, "silent", true, None);
        let found = tampered(&config(Some(image('a'))), &BTreeMap::new(), &inventory);
        let hosts: Vec<&str> = found.iter().map(|(_, h)| h.as_str()).collect();
        assert_eq!(hosts, vec!["liar"]);
        // With nothing kept there is nothing to be tampered relative to.
        assert!(tampered(&config(None), &BTreeMap::new(), &inventory).is_empty());
    }
}
