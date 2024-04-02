Huge Leather Lion

high

# Incorrect Evaluation of Presale Deadline Due to Incorrect Equality Operator in withdrawExcessToken()

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L385-L426
## Summary
The withdrawExcessToken function incorrectly evaluates the presale deadline due to an incorrectly set equality operator, potentially allowing unauthorized actions.
## Vulnerability Detail
The vulnerability arises from the following aspect of the code:
```solidity
 // initial liquidty provider can call this function after 30 days from genesis
        if (_genesis + _THIRTY_DAYS > timestamp) revert GoatErrors.PresaleDeadlineActive();//wrong use
        if (_vestingUntil != _MAX_UINT32) {
            revert GoatErrors.ActionNotAllowed();
        }
```
The condition _genesis + _THIRTY_DAYS > timestamp uses the greater-than operator (>). Which means Liquidity will not be able to call this function after _THIRTY_DAYS, but they will be able to do so before the _THIRTY_DAYS elapse. 
If the intention was to check if the current timestamp is after the presale deadline, the correct operator should be the less-than operator (<).
## Impact
Impact is high due to Unauthorized Actions as liquidity providers can call withdrawExcessToken() and rug the pool by running away with presale funds
## Code Snippet
```solidity
  function withdrawExcessToken() external {
        uint256 timestamp = block.timestamp;
        // initial liquidty provider can call this function after 30 days from genesis
        if (_genesis + _THIRTY_DAYS > timestamp) revert GoatErrors.PresaleDeadlineActive();//wrong use
        if (_vestingUntil != _MAX_UINT32) {
            revert GoatErrors.ActionNotAllowed();
        }

        address initialLiquidityProvider = _initialLPInfo.liquidityProvider;
        if (msg.sender != initialLiquidityProvider) {
            revert GoatErrors.Unauthorized();
        }

```
## Tool used

Manual Review

## Recommendation
To address this issue:

Replace the greater-than operator (>) with the less-than operator (<) to correctly evaluate the presale deadline.