use std::fmt;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{Sha256, Digest};

use super::hasher::Name;


#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Default, Eq)]
pub struct Sha256Hash(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);

impl From<Sha256Hash> for Vec<u8> {
    fn from(value: Sha256Hash) -> Self {
        Vec::from(value.0)
    }
}

impl From<Vec<u8>> for Sha256Hash {
    fn from(value: Vec<u8>) -> Self {
        Self(
            value
                .try_into()
                .expect("Failed converting Vec<u8> to Sha256Hash Type!"),
        )
    }
}

impl From<&[u8]> for Sha256Hash {
    fn from(value: &[u8]) -> Self {
        Self(
            value
                .try_into()
                .expect("Failed converting &[u8] to Sha256Hash Type!"),
        )
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Sha256Hash as fmt::Display>::fmt(self, f)
    }
}

impl Name for Sha256Hash {
    const NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("BLAKE3");
}

impl super::hasher::Hash<u8> for Sha256Hash {}

// Wrapper for the blake3 Hashing functionalities.
#[derive(Clone, Default, Debug)]
pub struct Sha256Hasher {
    state: Sha256,
    data: Vec<Vec<u8>>,
}
impl Serialize for Sha256Hasher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let state = self.state.clone();
        state.finalize().serialize(serializer)
    }
}
impl super::hasher::Hasher for Sha256Hasher {
    type Hash = Sha256Hash;
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;
    type NativeType = u8;

    fn new() -> Self {
        Self {
            state: sha2::Sha256::new(),
            data: vec![],
        }
    }

    fn reset(&mut self) {
        self.state.reset();
    }

    fn update(&mut self, data: &[u8]) {
        self.data.push(data.to_vec());
        self.state.update(data);
    }

    fn finalize(self) -> Sha256Hash {
        Sha256Hash(self.state.finalize().into())
    }

    fn finalize_reset(&mut self) -> Sha256Hash {
        println!("data: {:?}", self.data);
        self.data = vec![];
        Sha256Hash(self.state.finalize_reset().into())
    }

    unsafe fn hash_many_in_place(
        data: &[*const u8],
        single_input_length_bytes: usize,
        dst: &[*mut u8],
    ) {
        data.iter()
            .map(|p| std::slice::from_raw_parts(*p, single_input_length_bytes))
            .zip(
                dst.iter()
                    .map(|p| std::slice::from_raw_parts_mut(*p, Self::OUTPUT_SIZE)),
            )
            .for_each(|(input, out)| {
                let mut hasher = Sha256::new();
                hasher.update(input);
                hasher.finalize_into(out.into());
            })
    }
    
    
    fn hash_with_nonce(seed: &[Self::NativeType], nonce: u64) -> Self::Hash {
      let hash_input = seed
          .iter()
          .chain(nonce.to_le_bytes().iter())
          .cloned()
          .collect::<Vec<_>>();
      Sha256Hasher::hash(&hash_input)
  }
}

#[cfg(test)]
mod tests {
    use crate::commitment_scheme::sha256_hash::Sha256Hasher;
    use crate::commitment_scheme::hasher::Hasher;

    #[test]
    fn single_hash_test() {
        let hash_a = Sha256Hasher::hash(b"a");
        assert_eq!(
            hash_a.to_string(),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
    }

    #[test]
    fn hash_many_xof_test() {
        let input1 = "a";
        let input2 = "b";
        let input_arr = [input1.as_ptr(), input2.as_ptr()];

        let mut out = [0_u8; 96];
        let out_ptrs = [out.as_mut_ptr(), unsafe { out.as_mut_ptr().add(42) }];
        unsafe { Sha256Hasher::hash_many_in_place(&input_arr, 1, &out_ptrs) };

        assert_eq!("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb000000000000000000003e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d00000000000000000000000000000000000000000000", hex::encode(out));
    }

    #[test]
    fn hash_state_test() {
        let mut state = Sha256Hasher::new();
        state.update(b"a");
        state.update(b"b");
        let hash = state.finalize_reset();
        let hash_empty = state.finalize();

        assert_eq!(hash.to_string(), Sha256Hasher::hash(b"ab").to_string());
        assert_eq!(hash_empty.to_string(), Sha256Hasher::hash(b"").to_string())
    }
}
