package helpers

import "github.com/prysmaticlabs/prysm/v5/config/params"

// ChurnLimit for the current active balance, in gwei.
// New in EIP-7251: https://eips.ethereum.org/EIPS/eip-7251
//
// Spec definition:
//
//	def get_churn_limit(state: BeaconState) -> Gwei:
//	    """
//	    Return the churn limit for the current epoch.
//	    """
//	    churn = max(
//	        MIN_PER_EPOCH_CHURN_LIMIT_EIP7251,
//	        get_total_active_balance(state) // CHURN_LIMIT_QUOTIENT
//	    )
//	    return churn - churn % EFFECTIVE_BALANCE_INCREMENT
func ChurnLimit(activeBalanceGwei uint64) uint64 {
	churn := max(
		params.BeaconConfig().MinPerEpochChurnLimitElectra,
		(activeBalanceGwei / params.BeaconConfig().ChurnLimitQuotient),
	)
	return churn - churn%params.BeaconConfig().EffectiveBalanceIncrement
}

// ActivationExitChurnLimit for the current active balance, in gwei.
// New in EIP-7251: https://eips.ethereum.org/EIPS/eip-7251
//
// Spec definition:
//
//	def get_activation_exit_churn_limit(state: BeaconState) -> Gwei:
//	    """
//	    Return the churn limit for the current epoch dedicated to activations and exits.
//	    """
//	    return min(MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, get_churn_limit(state))
func ActivationExitChurnLimit(activeBalanceGwei uint64) uint64 {
	return min(params.BeaconConfig().MaxPerEpochActivationExitChurnLimit, ChurnLimit(activeBalanceGwei))
}
