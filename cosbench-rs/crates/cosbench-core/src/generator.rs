//! Name/size generators. Uniform over configured ranges (COSBench c()/u() simplified).

use crate::config::ObjectSpec;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct ObjectGenerator {
    spec: ObjectSpec,
}

impl ObjectGenerator {
    pub fn new(spec: ObjectSpec) -> Self {
        Self { spec }
    }

    pub fn random_container(&self, rng: &mut impl Rng) -> (u64, String) {
        let id = rng.gen_range(self.spec.containers.start..=self.spec.containers.end);
        (id, self.spec.container_name(id))
    }

    pub fn random_object(&self, rng: &mut impl Rng) -> (u64, String) {
        let id = rng.gen_range(self.spec.objects.start..=self.spec.objects.end);
        (id, self.spec.object_name(id))
    }

    pub fn sequential_object(&self, seq: u64) -> (u64, String) {
        let count = self.spec.objects.count();
        let id = self.spec.objects.start + (seq % count);
        (id, self.spec.object_name(id))
    }

    pub fn sequential_container(&self, seq: u64) -> (u64, String) {
        let count = self.spec.containers.count();
        let id = self.spec.containers.start + (seq % count);
        (id, self.spec.container_name(id))
    }

    /// Enumerate the full container × object cross product (COSBench
    /// prepare semantics): objects iterate fastest; the container advances
    /// after each full object range. seq 0..(containers*objects) covers
    /// every pair exactly once.
    pub fn sequential_pair(&self, seq: u64) -> ((u64, String), (u64, String)) {
        let oc = self.spec.objects.count();
        let cc = self.spec.containers.count();
        let oid = self.spec.objects.start + (seq % oc);
        let cid = self.spec.containers.start + ((seq / oc) % cc);
        (
            (cid, self.spec.container_name(cid)),
            (oid, self.spec.object_name(oid)),
        )
    }

    pub fn random_size(&self, rng: &mut impl Rng) -> u64 {
        let (lo, hi) = self.spec.effective_size_bounds();
        if lo == hi {
            lo
        } else {
            rng.gen_range(lo..=hi)
        }
    }

    pub fn all_containers(&self) -> impl Iterator<Item = String> + '_ {
        (self.spec.containers.start..=self.spec.containers.end).map(|i| self.spec.container_name(i))
    }

    pub fn all_objects(&self) -> impl Iterator<Item = (String, String)> + '_ {
        let c0 = self.spec.containers.start;
        let cname = self.spec.container_name(c0);
        (self.spec.objects.start..=self.spec.objects.end).map(move |oid| {
            (cname.clone(), self.spec.object_name(oid))
        })
    }

    pub fn hash_check(&self) -> bool {
        self.spec.hash_check
    }

    pub fn spec(&self) -> &ObjectSpec {
        &self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IdRange;

    #[test]
    fn sequential_pair_covers_cross_product() {
        let g = ObjectGenerator::new(ObjectSpec {
            cprefix: "c".into(),
            containers: IdRange { start: 1, end: 3 },
            oprefix: "o".into(),
            objects: IdRange { start: 1, end: 4 },
            size: 1,
            size_min: 0,
            size_max: 0,
            hash_check: false,
        });
        let mut seen = std::collections::HashSet::new();
        for seq in 0..12 {
            let ((cid, _), (oid, _)) = g.sequential_pair(seq);
            seen.insert((cid, oid));
        }
        // every (container, object) pair exactly once
        assert_eq!(seen.len(), 12);
    }
}
