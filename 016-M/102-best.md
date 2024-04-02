Brisk Shadow Tapir

medium

# lock of funds for the initial liquidity provider under some cicumstances

## Summary

if the initial liquidity provider withdraws lpTokens less than 25% of the total lp tokens that he has, some of it ill be locked until he has 1 wthdrawLeft , and he can be griefied by malicious users each week to not get that amount out.

## Vulnerability Detail

the protocol imlements liquidity locks where the initil lp shouldn't be able to withraw more than 25% a week. 
the amount that the admin can withdraw is stored in `_initialLPInfo.fractionalBalance`  , which is set initially to 25% of the liquidity.
but after each new mint the new fractionalbalance is calcualted like so :
```solidity=666
info.fractionalBalance = uint112(((info.fractionalBalance * info.withdrawalLeft) + liquidity) / 4);

```

but if the initial lp withdraws an amount that is less than fractionalBalance then the next time he adds liquidity , frational balance will be set to a wrong lower amount.
this amount will be locked for at most 3 other weeks, but a griefer can mint a minimal amount for the initial lp to lock it for another 4 weeks.

- let's assume that the initial liquidity provider has 100 lp token of pair tokenA/WETH, and the pool is in AMM phase
- the initial lp withdraws 5 lp tokens , lowering the withdrawalLeft to 3
- then the initial lp mints 100lp tokens , the calcualtion in `_updateInitialLpInfo` is `            info.fractionalBalance = uint112(((25 * 3) + 100) / 4);
` which is 175 / 4 = 43.75 
- meaning that he lost 20 lp tokens unless he reaches the final withdraw where he can withdraw the whole balance
- a malicious user can detect this and grief the user by minting a small amount to the victim leading to resetting the withdraw left counter to 4 meaning that the lp user has to wait 4 weeks to withdraw his lost balance.

## Impact

the initial lp can have some of his funds locked indefintly by griefer.

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/beb09519ad0c0ec0fdf5b96060fe5e4aafd71cff/goat-trading/contracts/exchange/GoatV1Pair.sol#L886-L909

## Tool used

Manual Review

