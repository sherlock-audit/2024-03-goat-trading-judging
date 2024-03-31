Agreeable Aquamarine Dog

medium

# Risk of Asset Loss Due to Non-Atomic Functions

## Summary
Directly calling the `GoatV1Pair` contract for depositing funds can result in asset loss for the user.

## Vulnerability Detail
The deposit function in the `GoatV1Pair` contract lacks atomicity. This means that if a user transfers assets to the contract and then calls the `mint()` function (or `swap()` or `burn()`), and the `mint()` function reverts while the token transfer succeeds, the user's funds will be trapped in the contract. Subsequently, the next depositor may unintentionally profit from these trapped funds, leading to financial loss for the initial user (User A).

Example of direct calls to the `mint()` function:

*   Transaction 1 (tx1): Transfer funds to the `GoatV1Pair` contract
*   Transaction 2 (tx2): Call the `mint()` function

Furthermore, as the `mint()` function and other related functions lack atomicity, a bot can execute a front-running attack to profit from the token transfer in tx1 before tx2 is executed.

## Impact
Users risk losing their assets due to this vulnerability.


## Code Snippet
[https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L114-L174](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L114-L174)

## Proof of concept

Following these steps, a user can lose their funds:

1.  Alice transfers assets to the `GoatV1Pair` contract.
    *   Funds are now held in the `GoatV1Pair` contract.
2.  Alice calls the `mint()` function on the `GoatV1Pair`.
    *   If the `mint()` function reverts, Alice's funds are lost.

Functions `mint()` and `swap()` have several reason to revert.

## Tool used

Manual analysis

## Recommendation

Only allow `Router` to call these functions.