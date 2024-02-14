// Copyright (C) 2019-2023 Aleo Systems Inc.
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

use console::{account::Address, network::prelude::*};
use ledger_committee::{Committee, MIN_DELEGATOR_STAKE};

use indexmap::IndexMap;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// A safety bound (sanity-check) for the coinbase reward.
const MAX_COINBASE_REWARD: u64 = ledger_block::MAX_COINBASE_REWARD; // Coinbase reward at block 1.

/// Returns the updated stakers reflecting the staking rewards for the given committee, block reward,
/// and validator commission rates.
///
/// The staking reward for validators is defined as: `block_reward * stake / total_stake + commission_to_recieve`.
/// The commission to receive for validators is defined as: `block_reward * (total_stake_delegated / total_stake) * (rate / 100)`.
///
/// The staking reward for delegators is defined as: `block_reward * stake / total_stake - commission_to_pay`.
/// The commission to pay for delegators is defined as: `block_reward * (stake / total_stake) * (rate / 100)`
///
/// This method ensures that stakers who are bonded to validators with more than **25%**
/// of the total stake will not receive a staking reward. In addition, this method
/// ensures stakers who have less than 10 credit are not eligible for a staking reward.
///
/// The choice of 25% is to ensure at least 4 validators are operational at any given time,
/// since our security model adheres to 3f+1, where f=1. As such, we tolerate Byzantine behavior
/// up to 33% of the total stake.
pub fn staking_rewards<N: Network>(
    stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
    committee: &Committee<N>,
    commission_rates: &IndexMap<Address<N>, u8>,
    block_reward: u64,
) -> IndexMap<Address<N>, (Address<N>, u64)> {
    // If the list of stakers is empty, there is no stake, or the block reward is 0, return the stakers.
    if stakers.is_empty() || committee.total_stake() == 0 || block_reward == 0 {
        return stakers.clone();
    }

    // Compute the updated stakers.
    cfg_iter!(stakers)
        .map(|(staker, (validator, stake))| {
            // If the validator has more than 25% of the total stake, skip the staker.
            let total_validator_stake = committee.get_stake(*validator);
            if total_validator_stake > committee.total_stake().saturating_div(4) {
                trace!("Validator {validator} has more than 25% of the total stake - skipping {staker}");
                return (*staker, (*validator, *stake));
            }
            // If the staker has less than the minimum required stake, skip the staker.
            if *stake < MIN_DELEGATOR_STAKE {
                trace!("Staker has less than {MIN_DELEGATOR_STAKE} microcredits - skipping {staker}");
                return (*staker, (*validator, *stake));
            }

            // Compute the numerator.
            let numerator = (block_reward as u128).saturating_mul(*stake as u128);
            // Compute the denominator.
            // Note: We guarantee this denominator cannot be 0 (as we return early if the total stake is 0).
            let denominator = committee.total_stake() as u128;
            // Compute the quotient.
            let quotient = numerator.saturating_div(denominator);
            // Ensure the staking reward is within a safe bound.
            if quotient > MAX_COINBASE_REWARD as u128 {
                error!("Staking reward ({quotient}) is too large - skipping {staker}");
                return (*staker, (*validator, *stake));
            }
            // Cast the staking reward as a u64.
            // Note: This '.expect' is guaranteed to be safe, as we ensure the quotient is within a safe bound.
            let staking_reward = u64::try_from(quotient).expect("Staking reward is too large");

            // Get the commission rate for the validator.
            let commission_rate = commission_rates.get(validator).copied().unwrap_or(0) as u128;

            // Update the staking reward with the commission.
            let staking_reward_after_commission = match staker == validator {
                // If the staker is the validator, add the total commission to the staking reward.
                true => {
                    // Calculate the total stake delegated to the validator.
                    let total_delegated_stake = total_validator_stake.saturating_sub(*stake);
                    // Compute the numerator.
                    let numerator = (block_reward as u128).saturating_mul(total_delegated_stake as u128);
                    // Compute the quotient. This quotient is the total staking reward recieved by delegators.
                    let quotient = numerator.saturating_div(denominator);
                    // Compute the commission.
                    let total_commission_to_receive = quotient.saturating_mul(commission_rate).saturating_div(100u128);
                    // Cast the commission as a u64.
                    // Note: This '.expect' is guaranteed to be safe, as we ensure the commission is within a safe bound.
                    let total_commission_to_receive =
                        u64::try_from(total_commission_to_receive).expect("Commission is too large");

                    // Add the commission to the validator staking reward.
                    staking_reward.saturating_add(total_commission_to_receive)
                }
                // If the staker is a delegator, subtract the commission from the staking reward.
                false => {
                    // Calculate the commission.
                    let commission = quotient.saturating_mul(commission_rate).saturating_div(100u128);

                    // Cast the commission as a u64.
                    // Note: This '.expect' is guaranteed to be safe, as we ensure the quotient is within a safe bound.
                    let commission_to_pay = u64::try_from(commission).expect("Commission is too large");

                    // Subtract the commission from the delegator staking reward.
                    staking_reward.saturating_sub(commission_to_pay)
                }
            };
            // Return the staker and the updated stake.
            (*staker, (*validator, stake.saturating_add(staking_reward_after_commission)))
        })
        .collect()
}

/// Returns the proving rewards for a given coinbase reward and list of prover solutions.
/// The prover reward is defined as: `puzzle_reward * (proof_target / combined_proof_target)`.
pub fn proving_rewards<N: Network>(
    proof_targets: Vec<(Address<N>, u64)>,
    puzzle_reward: u64,
) -> IndexMap<Address<N>, u64> {
    // Compute the combined proof target. Using '.sum' here is safe because we sum u64s into a u128.
    let combined_proof_target = proof_targets.iter().map(|(_, t)| *t as u128).sum::<u128>();

    // If the list of solutions is empty, the combined proof target is 0, or the puzzle reward is 0, return an empty map.
    if proof_targets.is_empty() || combined_proof_target == 0 || puzzle_reward == 0 {
        return Default::default();
    }

    // Initialize a vector to store the proving rewards.
    let mut rewards = IndexMap::<_, u64>::with_capacity(proof_targets.len());

    // Calculate the rewards for the individual provers.
    for (address, proof_target) in proof_targets {
        // Compute the numerator.
        let numerator = (puzzle_reward as u128).saturating_mul(proof_target as u128);
        // Compute the denominator.
        // Note: We guarantee this denominator cannot be 0 (to prevent a div by 0).
        let denominator = combined_proof_target.max(1);
        // Compute the quotient.
        let quotient = numerator.saturating_div(denominator);
        // Ensure the proving reward is within a safe bound.
        if quotient > MAX_COINBASE_REWARD as u128 {
            error!("Prover reward ({quotient}) is too large - skipping solution from {address}");
            continue;
        }
        // Cast the proving reward as a u64.
        // Note: This '.expect' is guaranteed to be safe, as we ensure the quotient is within a safe bound.
        let prover_reward = u64::try_from(quotient).expect("Prover reward is too large");
        // If there is a proving reward, append it to the vector.
        if prover_reward > 0 {
            // Add the proving reward to the prover.
            let entry = rewards.entry(address).or_default();
            *entry = entry.saturating_add(prover_reward);
        }
    }

    // Return the proving rewards.
    rewards
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{account::PrivateKey, prelude::TestRng};

    use indexmap::indexmap;

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: usize = 1000;

    #[test]
    fn test_staking_rewards() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = ledger_committee::test_helpers::sample_committee(rng);
        // Construct commission rates with fixed rate of 0.
        let commission_rates = crate::committee::test_helpers::sample_commission_rates(&committee, Some(0), rng);
        // Sample a random block reward.
        let block_reward = rng.gen_range(0..MAX_COINBASE_REWARD);
        // Retrieve an address.
        let address = *committee.members().iter().next().unwrap().0;

        for _ in 0..ITERATIONS {
            // Sample a random stake.
            let stake = rng.gen_range(MIN_DELEGATOR_STAKE..committee.total_stake());
            // Construct the stakers.
            let stakers = indexmap! {address => (address, stake)};
            let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, block_reward);
            assert_eq!(next_stakers.len(), 1);
            let (candidate_address, (candidate_validator, candidate_stake)) = next_stakers.into_iter().next().unwrap();
            assert_eq!(candidate_address, address);
            assert_eq!(candidate_validator, address);
            let reward = block_reward as u128 * stake as u128 / committee.total_stake() as u128;
            assert_eq!(candidate_stake, stake + u64::try_from(reward).unwrap(), "stake: {stake}, reward: {reward}");
        }
    }

    #[test]
    fn test_staking_rewards_with_commission() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = ledger_committee::test_helpers::sample_committee(rng);
        // Get the total stake of the committee.
        let total_stake = committee.total_stake();
        // Sample a random block reward.
        let block_reward = rng.gen_range(0..MAX_COINBASE_REWARD);
        // Retrieve an address.
        let validator_address = *committee.members().iter().next().unwrap().0;

        // Generate a delegator.
        let delegator_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let delegator_address = Address::<CurrentNetwork>::try_from(&delegator_private_key).unwrap();

        // Helper method to check that the delegator and validator stakes are calculated correctly.
        let check_expected_stake =
            |delegator_stake: u64,
             validator_stake: u64,
             commission_rate: u8,
             next_stakers: &IndexMap<Address<CurrentNetwork>, (Address<CurrentNetwork>, u64)>| {
                // Calculate the rewards.
                let delegator_reward = block_reward as u128 * delegator_stake as u128 / total_stake as u128;
                let validator_reward = block_reward as u128 * validator_stake as u128 / total_stake as u128;
                let delegator_commission = delegator_reward * commission_rate as u128 / 100;
                let expected_next_delegator_stake = delegator_stake + u64::try_from(delegator_reward).unwrap()
                    - u64::try_from(delegator_commission).unwrap();
                let expected_next_validator_stake = validator_stake
                    + u64::try_from(validator_reward).unwrap()
                    + u64::try_from(delegator_commission).unwrap();

                // Check that the rewards are as expected.
                assert_eq!(expected_next_delegator_stake, next_stakers.get(&delegator_address).unwrap().1);
                assert_eq!(expected_next_validator_stake, next_stakers.get(&validator_address).unwrap().1);
            };

        for _ in 0..ITERATIONS {
            // Sample a random stake.
            let delegator_stake = rng.gen_range(MIN_DELEGATOR_STAKE..committee.get_stake(validator_address));
            let validator_stake = committee.get_stake(validator_address) - delegator_stake;
            // Construct the stakers.
            let stakers = indexmap! {validator_address => (validator_address, validator_stake), delegator_address => (validator_address, delegator_stake)};

            // Construct commission rates with fixed rate of 0.
            {
                let commission_rates =
                    crate::committee::test_helpers::sample_commission_rates(&committee, Some(0), rng);
                let next_stakers =
                    staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, block_reward);

                // Check that the rewards are as expected.
                check_expected_stake(
                    delegator_stake,
                    validator_stake,
                    *commission_rates.get(&validator_address).unwrap(),
                    &next_stakers,
                );
            }

            // Construct commission rates with fixed rate of 100.
            {
                let commission_rates =
                    crate::committee::test_helpers::sample_commission_rates(&committee, Some(100), rng);
                let next_stakers =
                    staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, block_reward);

                // Check that the rewards are as expected.
                assert_eq!(delegator_stake, next_stakers.get(&delegator_address).unwrap().1);
                check_expected_stake(
                    delegator_stake,
                    validator_stake,
                    *commission_rates.get(&validator_address).unwrap(),
                    &next_stakers,
                );
            }

            // Check that a higher commission rate results in less rewards for the delegator and more rewards for the validator.
            {
                let lower_commission_rate = rng.gen_range(0..100) / 2;
                let higher_commission_rate = rng.gen_range((lower_commission_rate + 1)..=100);

                let lower_commission_rates = crate::committee::test_helpers::sample_commission_rates(
                    &committee,
                    Some(lower_commission_rate),
                    rng,
                );
                let higher_commission_rates = crate::committee::test_helpers::sample_commission_rates(
                    &committee,
                    Some(higher_commission_rate),
                    rng,
                );

                // Calculate the rewards for the lower commission rate.
                let next_stakers_lower_commission =
                    staking_rewards::<CurrentNetwork>(&stakers, &committee, &lower_commission_rates, block_reward);
                // Check that the rewards are as expected.
                check_expected_stake(
                    delegator_stake,
                    validator_stake,
                    *lower_commission_rates.get(&validator_address).unwrap(),
                    &next_stakers_lower_commission,
                );

                // Calculate the rewards for the higher commission rate.
                let next_stakers_higher_commission =
                    staking_rewards::<CurrentNetwork>(&stakers, &committee, &higher_commission_rates, block_reward);
                // Check that the rewards are as expected.
                check_expected_stake(
                    delegator_stake,
                    validator_stake,
                    *higher_commission_rates.get(&validator_address).unwrap(),
                    &next_stakers_higher_commission,
                );

                // Get the delegator and validator stakes for the lower commission rate.
                let delegator_stake_lower_commission = next_stakers_lower_commission.get(&delegator_address).unwrap().1;
                let validator_stake_lower_commission = next_stakers_lower_commission.get(&validator_address).unwrap().1;
                // Get the delegator and validator stakes for the higher commission rate.
                let delegator_stake_higher_commission =
                    next_stakers_higher_commission.get(&delegator_address).unwrap().1;
                let validator_stake_higher_commission =
                    next_stakers_higher_commission.get(&validator_address).unwrap().1;

                // Check that the delegator stake is lower for the higher commission rate.
                assert!(delegator_stake_higher_commission < delegator_stake_lower_commission);
                // Check that the validator stake is higher for the higher commission rate.
                assert!(validator_stake_higher_commission > validator_stake_lower_commission);
            }
        }
    }

    #[test]
    fn test_staking_rewards_large() {
        let rng = &mut TestRng::default();

        // Sample a random block reward.
        let block_reward = rng.gen_range(0..MAX_COINBASE_REWARD);
        // Sample a committee.
        let committee = ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 100, rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Construct commission rates with fixed rate of 0.
        let commission_rates = crate::committee::test_helpers::sample_commission_rates(&committee, Some(0), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Compute the staking rewards.
        let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, block_reward);
        println!("staking_rewards: {}ms", timer.elapsed().as_millis());
        assert_eq!(next_stakers.len(), stakers.len());
        for ((staker, (validator, stake)), (next_staker, (next_validator, next_stake))) in
            stakers.into_iter().zip(next_stakers.into_iter())
        {
            assert_eq!(staker, next_staker);
            assert_eq!(validator, next_validator);
            let reward = block_reward as u128 * stake as u128 / committee.total_stake() as u128;
            assert_eq!(stake + u64::try_from(reward).unwrap(), next_stake, "stake: {stake}, reward: {reward}");
        }
    }

    #[test]
    fn test_staking_rewards_when_staker_is_under_min_yields_no_reward() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = ledger_committee::test_helpers::sample_committee(rng);
        // Construct commission rates with fixed rate of 0.
        let commission_rates = crate::committee::test_helpers::sample_commission_rates(&committee, Some(0), rng);
        // Sample a random block reward.
        let block_reward = rng.gen_range(0..MAX_COINBASE_REWARD);
        // Retrieve an address.
        let address = *committee.members().iter().next().unwrap().0;

        for _ in 0..ITERATIONS {
            // Sample a random stake.
            let stake = rng.gen_range(0..MIN_DELEGATOR_STAKE);
            // Construct the stakers.
            let stakers = indexmap! {address => (address, stake)};
            let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, block_reward);
            assert_eq!(next_stakers.len(), 1);
            let (candidate_address, (candidate_validator, candidate_stake)) = next_stakers.into_iter().next().unwrap();
            assert_eq!(candidate_address, address);
            assert_eq!(candidate_validator, address);
            assert_eq!(candidate_stake, stake);
        }
    }

    #[test]
    fn test_staking_rewards_cannot_exceed_coinbase_reward() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = ledger_committee::test_helpers::sample_committee(rng);
        // Construct commission rates with fixed rate of 0.
        let commission_rates = crate::committee::test_helpers::sample_commission_rates(&committee, Some(0), rng);
        // Retrieve an address.
        let address = *committee.members().iter().next().unwrap().0;

        // Construct the stakers.
        let stakers = indexmap![address => (address, MIN_DELEGATOR_STAKE)];
        // Check that a maxed out coinbase reward, returns empty.
        let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, u64::MAX);
        assert_eq!(stakers, next_stakers);

        // Ensure a staking reward that is too large, renders no rewards.
        for _ in 0..ITERATIONS {
            // Sample a random overly-large block reward.
            let block_reward = rng.gen_range(MAX_COINBASE_REWARD..u64::MAX);
            // Sample a random stake.
            let stake = rng.gen_range(MIN_DELEGATOR_STAKE..u64::MAX);
            // Construct the stakers.
            let stakers = indexmap![address => (address, stake)];
            // Check that an overly large block reward fails.
            let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, &commission_rates, block_reward);
            assert_eq!(stakers, next_stakers);
        }
    }

    #[test]
    fn test_staking_rewards_is_empty() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = ledger_committee::test_helpers::sample_committee(rng);
        // Construct commission rates with fixed rate of 0.
        let commission_rates = crate::committee::test_helpers::sample_commission_rates(&committee, Some(0), rng);

        // Compute the staking rewards (empty).
        let rewards = staking_rewards::<CurrentNetwork>(&indexmap![], &committee, &commission_rates, rng.gen());
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_proving_rewards() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random address.
            let address = Address::rand(rng);
            // Sample a random puzzle reward.
            let puzzle_reward = rng.gen_range(0..MAX_COINBASE_REWARD);

            let rewards = proving_rewards::<CurrentNetwork>(vec![(address, u64::MAX)], puzzle_reward);
            assert_eq!(rewards.len(), 1);
            let (candidate_address, candidate_amount) = rewards.into_iter().next().unwrap();
            assert_eq!(candidate_address, address);
            assert!(candidate_amount <= puzzle_reward);
        }
    }

    #[test]
    fn test_proving_rewards_cannot_exceed_coinbase_reward() {
        let rng = &mut TestRng::default();

        // Ensure a proving reward that is too large, renders no rewards.
        for _ in 0..ITERATIONS {
            // Sample a random address.
            let address = Address::rand(rng);
            // Sample a random overly-large puzzle reward.
            let puzzle_reward = rng.gen_range(MAX_COINBASE_REWARD..u64::MAX);
            // Sample a random proof target.
            let proof_target = rng.gen_range(0..u64::MAX);
            // Check that a maxed out proof target fails.
            let rewards = proving_rewards::<CurrentNetwork>(vec![(address, proof_target)], puzzle_reward);
            assert!(rewards.is_empty());
        }
    }

    #[test]
    fn test_proving_rewards_is_empty() {
        let rng = &mut TestRng::default();
        // Sample a random address.
        let address = Address::rand(rng);

        // Compute the proving rewards (empty).
        let rewards = proving_rewards::<CurrentNetwork>(vec![], rng.gen());
        assert!(rewards.is_empty());

        // Check that a maxed out coinbase reward, returns empty.
        let rewards = proving_rewards::<CurrentNetwork>(vec![(address, 2)], u64::MAX);
        assert!(rewards.is_empty());

        // Ensure a 0 coinbase reward case is empty.
        let rewards = proving_rewards::<CurrentNetwork>(vec![(address, 2)], 0);
        assert!(rewards.is_empty());
    }
}
