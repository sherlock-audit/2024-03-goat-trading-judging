Daring Champagne Scallop

medium

# It's possible to create pairs that cannot be taken over

## Summary

It's possible to create pairs that cannot be taken over and DOS a pair forever.

## Vulnerability Detail

A pair is created by calling [createPair()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L33) which takes the initial parameters of the pair as inputs but the initial parameters are never verified, which makes it possible for an attacker to create a token pair that's impossible to recover via [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452).

There's more ways to create a pair that cannot be taken over, a simple example is to set all of the initial parameters to the maximum possible value:

```solidity
uint112 virtualEth = type(uint112).max;
uint112 bootstrapEth = type(uint112).max;
uint112 initialEth = type(uint112).max;
uint112 initialTokenMatch = type(uint112).max;
```

This will make [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452) revert for overflow on the internal call to [_tokenAmountsForLiquidityBootstrap](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L859-L862):

```solidity
uint256 k = virtualEth * initialTokenMatch;
@> tokenAmtForAmm = (k * bootstrapEth) / (totalEth * totalEth);
```

Here `virtualEth`, `initialTokenMatch` and `bootstrapEth` are all setted to `type(uint112).max`. The multiplication `virtualEth * initialTokenMatch * bootstrapEth` performed to calculate `tokenAmtForAmm` will revert for overflow because `2^112 * 2^112 * 2^112 = 2^336` which is bigger than `2^256`.

## Impact

Creation of new pairs can be DOSed forever.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Validate a pair initial parameters and mint liquidity on pool creation.