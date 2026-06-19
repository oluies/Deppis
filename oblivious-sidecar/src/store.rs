//! Oblivious PONG message store (T052, D7/FR-014).

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub const TOKEN_LEN: usize = 32;
pub const FRAME_LEN: usize = 256;

#[derive(Clone, Copy)]
struct Slot {
    occupied: u8, // 0 or 1
    token: [u8; TOKEN_LEN],
    frame: [u8; FRAME_LEN],
}

impl Slot {
    fn empty() -> Self {
        Slot { occupied: 0, token: [0u8; TOKEN_LEN], frame: [0u8; FRAME_LEN] }
    }
}

/// Fixed-capacity oblivious message store. Every `write` and `read` touches EVERY slot with
/// identical constant-time operations, so the access pattern depends only on the public capacity —
/// never on the token value or on which slot matched (the obliviousness invariant the PONG role
/// must keep; the real enclave adds bins/deamortized builds for throughput, deferred).
///
/// Reads are single-use: a matched slot is cleared AND its token/frame bytes zeroized, so a token
/// never yields a frame twice (non-recurrence, FR-014) and no sealed payload lingers in memory. A
/// read ALWAYS returns a `FRAME_LEN` blob — carrier zeros on miss — so hit-vs-miss is not
/// observable from the result shape (matches the sealed, byte-uniform contract).
pub struct ObliviousStore {
    slots: Vec<Slot>,
    // Test-only instrumentation: number of slots touched by the last write/read. Lets unit tests
    // assert the full-scan (obliviousness) invariant. Only present in `cfg(test)` builds.
    #[cfg(test)]
    touches: std::cell::Cell<usize>,
}

impl ObliviousStore {
    pub fn with_capacity(n: usize) -> Self {
        ObliviousStore {
            slots: vec![Slot::empty(); n],
            #[cfg(test)]
            touches: std::cell::Cell::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Place `(token, frame)` into the first free slot, obliviously (scan all, conditionally write
    /// exactly one). Returns false iff the store is full — capacity is public, so this is the only
    /// data-independent signal.
    pub fn write(&mut self, token: &[u8; TOKEN_LEN], frame: &[u8; FRAME_LEN]) -> bool {
        let mut placed = Choice::from(0u8);
        #[cfg(test)]
        let mut touched = 0usize;
        for slot in self.slots.iter_mut() {
            let is_free = slot.occupied.ct_eq(&0u8);
            let take = is_free & !placed; // first free slot only
            slot.occupied.conditional_assign(&1u8, take);
            for k in 0..TOKEN_LEN {
                slot.token[k].conditional_assign(&token[k], take);
            }
            for k in 0..FRAME_LEN {
                slot.frame[k].conditional_assign(&frame[k], take);
            }
            placed = placed | take;
            #[cfg(test)]
            {
                touched += 1;
            }
        }
        #[cfg(test)]
        self.touches.set(touched);
        bool::from(placed)
    }

    /// Single-use read by token. Returns the matching frame, or carrier zeros on miss; the matched
    /// slot is cleared and zeroized so the token cannot be read again and no payload lingers.
    /// Touches every slot identically.
    pub fn read(&mut self, token: &[u8; TOKEN_LEN]) -> [u8; FRAME_LEN] {
        let mut result = [0u8; FRAME_LEN];
        #[cfg(test)]
        let mut touched = 0usize;
        for slot in self.slots.iter_mut() {
            let occ = slot.occupied.ct_eq(&1u8);
            let matches = occ & slot.token.as_slice().ct_eq(token.as_slice());
            for k in 0..FRAME_LEN {
                result[k].conditional_assign(&slot.frame[k], matches); // capture frame first
                slot.frame[k].conditional_assign(&0u8, matches); // then erase on consume
            }
            for k in 0..TOKEN_LEN {
                slot.token[k].conditional_assign(&0u8, matches); // erase token on consume
            }
            slot.occupied.conditional_assign(&0u8, matches); // mark free (non-recurrent)
            #[cfg(test)]
            {
                touched += 1;
            }
        }
        #[cfg(test)]
        self.touches.set(touched);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(b: u8) -> [u8; TOKEN_LEN] {
        [b; TOKEN_LEN]
    }
    fn frame(b: u8) -> [u8; FRAME_LEN] {
        [b; FRAME_LEN]
    }

    #[test]
    fn read_touches_every_slot_regardless_of_hit_position() {
        // hit in the first slot
        let mut s = ObliviousStore::with_capacity(16);
        assert!(s.write(&tok(1), &frame(1)));
        let _ = s.read(&tok(1));
        assert_eq!(s.touches.get(), 16);

        // hit in the last slot
        let mut s2 = ObliviousStore::with_capacity(16);
        for i in 0..15u8 {
            assert!(s2.write(&tok(i + 1), &frame(0)));
        }
        assert!(s2.write(&tok(200), &frame(9))); // lands in slot 15
        assert_eq!(s2.read(&tok(200)), frame(9));
        assert_eq!(s2.touches.get(), 16);

        // miss
        let mut s3 = ObliviousStore::with_capacity(16);
        let _ = s3.read(&tok(99));
        assert_eq!(s3.touches.get(), 16);
    }

    #[test]
    fn consumed_slot_is_zeroized() {
        let mut s = ObliviousStore::with_capacity(4);
        assert!(s.write(&tok(5), &frame(7)));
        let _ = s.read(&tok(5));
        assert!(s.slots.iter().all(|sl| sl.occupied == 0
            && sl.token == [0u8; TOKEN_LEN]
            && sl.frame == [0u8; FRAME_LEN]));
    }
}
