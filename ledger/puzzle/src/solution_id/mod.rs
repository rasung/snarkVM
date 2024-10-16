// Copyright 2024 Aleo Network Foundation
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod bytes;
mod serialize;
mod string;

pub use string::SOLUTION_ID_PREFIX;

use console::{account::Address, network::prelude::*};
use snarkvm_algorithms::crypto_hash::sha256d_to_u64;

use core::marker::PhantomData;

/// The solution ID.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct SolutionID<N: Network>(u64, PhantomData<N>);

impl<N: Network> From<u64> for SolutionID<N> {
    /// Initializes a new instance of the solution ID.
    fn from(nonce: u64) -> Self {
        Self(nonce, PhantomData)
    }
}

impl<N: Network> SolutionID<N> {
    /// Initializes the solution ID from the given epoch hash, address, and counter.
    pub fn new(epoch_hash: N::BlockHash, address: Address<N>, counter: u64) -> Result<Self> {
        // Construct the nonce as sha256d(epoch_hash_bytes_le[0..8] || address || counter).
        let mut bytes_le = Vec::new();
        let lower_bytes = &epoch_hash.to_bytes_le()?[0..8];
        bytes_le.extend_from_slice(lower_bytes);
        bytes_le.extend_from_slice(&address.to_bytes_le()?);
        bytes_le.extend_from_slice(&counter.to_bytes_le()?);

        println!("epoch_hash : {} address : {} counter : {}", epoch_hash, address, counter);
        
        // 2024-10-16T12:56:48.067891Z DEBUG snarkos_node::prover: == 123 == Proving 'Puzzle' for Epoch 'ab1ru65v0sq3r9dm..' (Coinbase Target 33778304674580, Proof Target 8444576168646)
        // lower_bytes: [31, 53, 70, 62, 0, 136, 202, 221], address: [32, 248, 67, 10, 235, 44, 83, 181, 45, 170, 182, 71, 6, 98, 121, 47, 252, 163, 132, 138, 173, 188, 215, 143, 103, 147, 79, 252, 15, 144, 189, 3], counter: [79, 21, 200, 135, 112, 65, 48, 112]
        // 2024-10-16T12:56:48.068586Z DEBUG snarkos_node::prover: == 123 == Proving 'Puzzle' for Epoch 'ab1ru65v0sq3r9dm..' (Coinbase Target 33778304674580, Proof Target 8444576168646)
        // lower_bytes: [31, 53, 70, 62, 0, 136, 202, 221], address: [32, 248, 67, 10, 235, 44, 83, 181, 45, 170, 182, 71, 6, 98, 121, 47, 252, 163, 132, 138, 173, 188, 215, 143, 103, 147, 79, 252, 15, 144, 189, 3], counter: [205, 69, 1, 95, 202, 24, 124, 128]
        println!(
            "lower_bytes: {:?}, address: {:?}, counter: {:?}",
            lower_bytes,
            &address.to_bytes_le().unwrap_or_else(|e| {
                println!("Error converting address to bytes: {:?}", e);
                vec![] // 에러가 발생한 경우 빈 벡터 반환
            }),
            &counter.to_bytes_le().unwrap_or_else(|e| {
                println!("Error converting counter to bytes: {:?}", e);
                vec![] // 에러가 발생한 경우 빈 벡터 반환
            })
        );





        Ok(Self::from(sha256d_to_u64(&bytes_le)))
    }
}

impl<N: Network> Deref for SolutionID<N> {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
