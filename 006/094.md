Brisk Shadow Tapir

medium

# Initial Liquidity provider can bypass the withdrawal limit

## Summary

the initial liquidity provider can bypass maximum withdrawal limit and withdraw all the liquidity that he has leading to a rug pull.

## Vulnerability Detail

According to the protocol documentation, mandatory liquidity locks are implemented, restricting the initial liquidity provider to withdraw only 25% of their liquidity each week. The check for this restriction is enforced within the `_beforeTokenTransfer` function as follows: 
```solidity=910
if (amount > lpInfo.fractionalBalance) {
                    revert GoatErrors.BurnLimitExceeded();
                }
```
but this check isn't done if the number of withdrawals left for the lp is 1.
so the initial liquidity provider can withdraw the whole amount of lp tokens that he has, bypassing the 25% limit.

## Proof of Concept:

- Assume the initial liquidity provider holds 100 LP tokens of the pair tokenA/WETH, and the pool is in the AMM phase.
- Over the first three weeks, they burn 1 LP token each week.
- By the fourth week, they have 97 LP tokens remaining, and they withdraw all of them.
- This action effectively results in a rug pull, harming the users of the protocol.

## Impact

a key invariant of the system gets breached by having the inital liquidity provider able to bypass the withdraw limit

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/beb09519ad0c0ec0fdf5b96060fe5e4aafd71cff/goat-trading/contracts/exchange/GoatV1Pair.sol#L886-L909

## Tool used

Manual Review