Hollow Bone Horse

medium

# Discrepancy in Token Balance Calculation Leading to Potential Liquidity Drain(edge case)

## Summary
The `withdrawExcessToken` function in the `GoatV1Pair` contract can incorrectly calculate the amount of excess tokens to be withdrawn by the initial liquidity provider, potentially leading to a drain of liquidity from the pool.


## Vulnerability Detail
1. How it exists?
 : The `withdrawExcessToken` function calculates the amount of excess tokens based on state variables `(_reserveEth, _virtualEth, _bootstrapEth, _initialTokenMatch)` without verifying the actual token balance in the contract.
```solidity
// @audit ... (within withdrawExcessToken function)
uint256 poolTokenBalance = token.balanceOf(address(this));
uint256 amountToTransferBack = poolTokenBalance - tokenAmtForAmm;
token.safeTransfer(initialLiquidityProvider, amountToTransferBack);
// ...
```

2. What Goes Wrong?
: If the actual token balance is less than the expected amount (due to a bug, external contract interaction, or malicious activity), the initial LP could withdraw more tokens than they are entitled to, depleting the pool's liquidity.

3. Why?
: The vulnerability could be exploited either unintentionally due to a lack of awareness of the actual token balance or intentionally if someone aims to drain liquidity from the pool.

4. Here's a potential exploit scenario in simple words:

- The pool doesn't reach the bootstrap goal within a month.
- The initial LP calls `withdrawExcessToken.`
- The function calculates the token amount to withdraw based on virtual reserves and initial match `(_tokenAmountsForLiquidityBootstrap).`
- Due to other interactions with the pool (e.g., swaps, fees), the actual token balance might be higher than the calculated amount for AMM conversion.
- The LP withdraws this excess, which could be more than intended, potentially draining liquidity.


## Impact
If exploited, this vulnerability could lead to a significant loss of funds for the pool, affecting all liquidity providers.

## Code Snippet
https://github.com/sherlock-audit/2024-03-goat-trading/blob/beb09519ad0c0ec0fdf5b96060fe5e4aafd71cff/goat-trading/contracts/exchange/GoatV1Pair.sol#L413-L417

## Tool used

Manual Review

## Recommendation
- Directly check the actual token balance `(IERC20(_token).balanceOf(address(this)))` against the expected balance based on the pool's state.
- Introduce a mechanism to pause the withdrawal function and alert the contract owner or governance mechanism in case of a detected discrepancy, allowing for manual intervention and investigation.