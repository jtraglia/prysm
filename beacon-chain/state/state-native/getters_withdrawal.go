package state_native

import (
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
	mathutil "github.com/prysmaticlabs/prysm/v5/math"
	enginev1 "github.com/prysmaticlabs/prysm/v5/proto/engine/v1"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/runtime/version"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
)

const ETH1AddressOffset = 12

// NextWithdrawalIndex returns the index that will be assigned to the next withdrawal.
func (b *BeaconState) NextWithdrawalIndex() (uint64, error) {
	if b.version < version.Capella {
		return 0, errNotSupported("NextWithdrawalIndex", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.nextWithdrawalIndex, nil
}

// NextWithdrawalValidatorIndex returns the index of the validator which is
// next in line for a withdrawal.
func (b *BeaconState) NextWithdrawalValidatorIndex() (primitives.ValidatorIndex, error) {
	if b.version < version.Capella {
		return 0, errNotSupported("NextWithdrawalValidatorIndex", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.nextWithdrawalValidatorIndex, nil
}

// ExpectedWithdrawals returns the withdrawals that a proposer will need to pack in the next block
// applied to the current state. It is also used by validators to check that the execution payload carried
// the right number of withdrawals
func (b *BeaconState) ExpectedWithdrawals() ([]*enginev1.Withdrawal, error) {
	if b.version < version.Capella {
		return nil, errNotSupported("ExpectedWithdrawals", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	withdrawals := make([]*enginev1.Withdrawal, 0, params.BeaconConfig().MaxWithdrawalsPerPayload)
	validatorIndex := b.nextWithdrawalValidatorIndex
	withdrawalIndex := b.nextWithdrawalIndex
	epoch := slots.ToEpoch(b.slot)

	validatorsLen := b.validatorsLen()
	bound := mathutil.Min(uint64(validatorsLen), params.BeaconConfig().MaxValidatorsPerWithdrawalsSweep)
	for i := uint64(0); i < bound; i++ {
		val, err := b.validatorAtIndex(validatorIndex)
		if err != nil {
			return nil, errors.Wrapf(err, "could not retrieve validator at index %d", validatorIndex)
		}
		balance, err := b.balanceAtIndex(validatorIndex)
		if err != nil {
			return nil, errors.Wrapf(err, "could not retrieve balance at index %d", validatorIndex)
		}
		if balance > 0 && isFullyWithdrawableValidator(val, epoch) {
			withdrawals = append(withdrawals, &enginev1.Withdrawal{
				Index:          withdrawalIndex,
				ValidatorIndex: validatorIndex,
				Address:        bytesutil.SafeCopyBytes(val.WithdrawalCredentials[ETH1AddressOffset:]),
				Amount:         balance,
			})
			withdrawalIndex++
		} else if isPartiallyWithdrawableValidator(val, balance) {
			withdrawals = append(withdrawals, &enginev1.Withdrawal{
				Index:          withdrawalIndex,
				ValidatorIndex: validatorIndex,
				Address:        bytesutil.SafeCopyBytes(val.WithdrawalCredentials[ETH1AddressOffset:]),
				Amount:         balance - params.BeaconConfig().MaxEffectiveBalance,
			})
			withdrawalIndex++
		}
		if uint64(len(withdrawals)) == params.BeaconConfig().MaxWithdrawalsPerPayload {
			break
		}
		validatorIndex += 1
		if uint64(validatorIndex) == uint64(validatorsLen) {
			validatorIndex = 0
		}
	}
	return withdrawals, nil
}

// hasETH1WithdrawalCredential returns whether the validator has an ETH1
// Withdrawal prefix. It assumes that the caller has a lock on the state
func hasETH1WithdrawalCredential(val *ethpb.Validator) bool {
	if val == nil {
		return false
	}
	cred := val.WithdrawalCredentials
	return len(cred) > 0 && cred[0] == params.BeaconConfig().ETH1AddressWithdrawalPrefixByte
}

// isFullyWithdrawableValidator returns whether the validator is able to perform a full
// withdrawal. This differ from the spec helper in that the balance > 0 is not
// checked. This function assumes that the caller holds a lock on the state
func isFullyWithdrawableValidator(val *ethpb.Validator, epoch primitives.Epoch) bool {
	if val == nil {
		return false
	}
	return hasETH1WithdrawalCredential(val) && val.WithdrawableEpoch <= epoch
}

// isPartiallyWithdrawable returns whether the validator is able to perform a
// partial withdrawal. This function assumes that the caller has a lock on the state
func isPartiallyWithdrawableValidator(val *ethpb.Validator, balance uint64) bool {
	if val == nil {
		return false
	}
	hasMaxBalance := val.EffectiveBalance == params.BeaconConfig().MaxEffectiveBalance
	hasExcessBalance := balance > params.BeaconConfig().MaxEffectiveBalance
	return hasETH1WithdrawalCredential(val) && hasExcessBalance && hasMaxBalance
}

// TODO: This goes in exits file?
// ExitEpochAndUpdateChurn
//
// Spec definition:
//
//	def compute_exit_epoch_and_update_churn(state: BeaconState, exit_balance: Gwei) -> Epoch:
//	    earliest_exit_epoch = compute_activation_exit_epoch(get_current_epoch(state))
//	    per_epoch_churn = get_activation_exit_churn_limit(state)
//	    # New epoch for exits.
//	    if state.earliest_exit_epoch < earliest_exit_epoch:
//	        state.earliest_exit_epoch = earliest_exit_epoch
//	        state.exit_balance_to_consume = per_epoch_churn
//
//	    if exit_balance <= state.exit_balance_to_consume:
//	        # Exit fits in the current earliest epoch.
//	        state.exit_balance_to_consume -= exit_balance
//	    else:
//	        # Exit doesn't fit in the current earliest epoch.
//	        balance_to_process = exit_balance - state.exit_balance_to_consume
//	        additional_epochs, remainder = divmod(balance_to_process, per_epoch_churn)
//	        state.earliest_exit_epoch += additional_epochs + 1
//	        state.exit_balance_to_consume = per_epoch_churn - remainder
//
// return state.earliest_exit_epoch
func (b *BeaconState) ExitEpochAndUpdateChurn(exitBalance uint64) (primitives.Epoch, error) {
	if b.version < version.Electra {
		return 0, errNotSupported("ExitEpochAndUpdateChurn", b.version)
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	earliestExitEpoch := helpers.ActivationExitEpoch(slots.ToEpoch(b.slot))
	activeBal, err := helpers.TotalActiveBalance(b)
	if err != nil {
		return 0, err
	}
	// Guaranteed to be non-zero.
	perEpochChurn := helpers.ActivationExitChurnLimit(helpers.ActivationExitChurnLimit(activeBal))

	// New epoch for exits
	if b.earliestExitEpoch < earliestExitEpoch {
		b.earliestExitEpoch = earliestExitEpoch
		b.exitBalanceToConsume = perEpochChurn
	}

	if exitBalance <= b.exitBalanceToConsume {
		b.exitBalanceToConsume -= exitBalance
	} else {
		// exit doesn't fit in the current earliest epoch
		balanceToProcess := exitBalance - b.exitBalanceToConsume
		additionalEpochs, remainder := balanceToProcess/perEpochChurn, balanceToProcess%perEpochChurn
		b.earliestExitEpoch += primitives.Epoch(additionalEpochs + 1)
		b.exitBalanceToConsume = perEpochChurn - remainder
	}

	return b.earliestExitEpoch, nil
}
