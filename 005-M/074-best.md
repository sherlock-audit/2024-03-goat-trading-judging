Great Grape Ram

medium

# Mev check cannot prevent sandwich attack.

## Summary

An attacker can conduct a sandwich attack through two consecutive blocks.

## Vulnerability Detail

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L743-L766

```javascript
    function _handleMevCheck(bool isBuy) internal {
        // @note  Known bug for chains that have block time less than 2 second
        uint8 swapType = isBuy ? 1 : 2;
        uint32 timestamp = uint32(block.timestamp);
        uint32 lastTrade = _lastTrade;
        if (lastTrade < timestamp) {
            lastTrade = timestamp;
        } else if (lastTrade == timestamp) {
            lastTrade = timestamp + swapType;
        } else if (lastTrade == timestamp + 1) {
            if (swapType == 2) {
                revert GoatErrors.MevDetected1();
            }
        } else if (lastTrade == timestamp + 2) {
            if (swapType == 1) {
                revert GoatErrors.MevDetected2();
            }
        } else {
            // make it bullet proof
            revert GoatErrors.MevDetected();
        }
        // update last trade
        _lastTrade = lastTrade;
    }
```

Let's consider the following scenario: 
1. Assume the pool reserves are `10,000 WETH` and `100,000,000 token`.
2. An attacker monitors a swap transaction without a slippage parameter. 
3. A user attempts to buy token with `10 WETH` but forgets to set the slippage parameter `amountOutMin`. Anyway, the user expects to receive approximately `100,000,000 * 10 / (10,000 + 10) = 99,900.1 token`.
4. The attacker front-runs by executing a transaction to buy `token` with `990,000 WETH`, obtaining `99,000,000 token`. This action alters the pool's state to:
    `WETH`  : 1,000,000,
    `token`  : 1,000,000.
5. Consequently, the victim user only receives around `1,000,000 * 10 / (1,000,000 + 10) = 10 token`, leading to a new pool state of: 
    `WETH`  : 1,000,010, 
    `token`  : 999,990. 
6. The attacker proceeds to sell token to repurchase `990,000 WETH` as the first transaction of the next block, to avoid MEV check. To execute this transaction, the attacker needs to sell approximately `990,010 * 999,990 / (1,000,010 - 990,000) = 98,901,109 token`, resulting in the attacker obtaining `98,891 token` for free.

The above scenario lacks precision as it does not account for fees. However, the concept of a sandwich attack through two consecutive transactions is significant.

## Impact

If a user conducts a swap transaction without a slippage parameter, an attacker can unfairly profit from a sandwich attack across two consecutive blocks.

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L743-L766

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L149-159

## Tool used

Manual Review

## Recommendation

The MEV check needs improvement.