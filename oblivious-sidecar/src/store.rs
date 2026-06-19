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
/// Reads are single-use: a matched slot is cleared, so a token never yields a frame twice
/// (non-recurrence, FR-014). A read ALWAYS returns a `FRAME_LEN` blob — carrier zeros on miss — so
/// hit-vs-miss is not observable from the result shape (matches the sealed, byte-uniform contract).
pub struct ObliviousStore {
    slots: Vec<Slot>,
}

impl ObliviousStore {
    pub fn with_capacity(n: usize) -> Self {
        ObliviousStore { slots: vec![Slot::empty(); n] }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Place `(token, frame)` into the first free slot, obliviously (scan all, conditionally write
    /// exactly one). Returns false iff the store is full — capacity is public, so this is the only
    /// data-independent signal.
    pub fn write(&mut self, token: &[u8; TOKEN_LEN], frame: &[u8; FRAME_LEN]) -> bool {
        let mut placed = Choice::from(0u8);
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
        }
        bool::from(placed)
    }

    /// Single-use read by token. Returns the matching frame, or carrier zeros on miss; the matched
    /// slot is cleared so the token cannot be read again. Touches every slot identically.
    pub fn read(&mut self, token: &[u8; TOKEN_LEN]) -> [u8; FRAME_LEN] {
        let mut result = [0u8; FRAME_LEN];
        for slot in self.slots.iter_mut() {
            let occ = slot.occupied.ct_eq(&1u8);
            let matches = occ & slot.token.as_slice().ct_eq(token.as_slice());
            for k in 0..FRAME_LEN {
                result[k].conditional_assign(&slot.frame[k], matches);
            }
            slot.occupied.conditional_assign(&0u8, matches); // consume (non-recurrent)
        }
        result
    }
}
