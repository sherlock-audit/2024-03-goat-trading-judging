Daring Champagne Scallop

high

# The `takeOverPool()` can be frontrun to steal funds

## Summary
The [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452) requires to transfer tokens and WETH in the pool before being called and it can be front-run to steal funds.

## Vulnerability Detail
The [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452) function allows a team to take over a pool from malicious actors. To do so the caller is required to transfer tokens and WETH to the pair before calling [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452).

Because there is a delay between when the tokens and WETH are transferred and the call to [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452) and attacker can insert a transaction in-between to steal funds. This can be done with a call to [swap()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L242).

Note that the router does not implement any function that allows to call [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452) safely.

## Impact
A malicious actor can steal funds and prevent a pool from being taken over.

## Code Snippet

## Tool used

Manual Review

## Recommendation
Implement a function in the router that performs correct safety checks and allows a team to safely call [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452).
