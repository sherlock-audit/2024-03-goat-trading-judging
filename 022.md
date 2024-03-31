Sticky Flaxen Rat

medium

# Casting of `GoatV1Pair.sol:_pendingProtocolFees` to `uint72` from `uint256` can lead to lost of Treasury  Fees

## Summary

The [GoatV1Pair.sol:_handleFee](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L693) calculates and handles the distribution of fees for each swap transaction. It gives 60% of fees to the treasury. The problem here is that initially the [GoatV1Pair.sol:pendingProtocolFees](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L708) representing the Treasury  Fee is in `uint256` and it is later cast to `uint72` [GoatV1Pair.sol:_pendingProtocolFees](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L762) this can lead to the lose of Funds when the `GoatV1Pair.sol:_pendingProtocolFees` go above the max value of `uint72` which is `4722366482869645213695` wei.

## Vulnerability Details

From the code below `pendingProtocolFees`  stores the fees pending, the `minCollectableFees` read ['GoatV1Factory.sol:minCollectableFees'](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L22) to get minimum collectable fee from the factory, and performs a check, `if (pendingProtocolFees > minCollectableFees)` if the condition is `true` it sends the `pendingProtocolFees` to the Treasury and set `pendingProtocolFees = 0`, but if this condition is not met `pendingProtocolFees` accumulate. Finally the `_pendingProtocolFees = uint72(pendingProtocolFees)` is set and the casting is done.

```solidity

    function _handleFees(uint256 amountWethIn, uint256 amountWethOut, bool isPresale)
        internal
        returns (uint256 feesCollected, uint256 feesLp)
    {
        ...
@->     uint256 pendingProtocolFees = _pendingProtocolFees;

        // lp fees only updated if it's not a presale
        if (!isPresale) {
            _pendingLiquidityFees += uint112(feesLp);
            // update fees per token stored
            feesPerTokenStored += uint184((feesLp * 1e18) / totalSupply());
        }

        pendingProtocolFees += feesCollected - feesLp;

        IGoatV1Factory _factory = IGoatV1Factory(factory);
@->     uint256 minCollectableFees = _factory.minimumCollectableFees();

@->     if (pendingProtocolFees > minCollectableFees) {
            IERC20(_weth).safeTransfer(_factory.treasury(), pendingProtocolFees);
            pendingProtocolFees = 0;
        }
@->     _pendingProtocolFees = uint72(pendingProtocolFees);
    }


```

The Vulnerability arises from the fact that ['GoatV1Factory.sol:minCollectableFees'](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L22) can be updated by the Treasury  ['GoatV1Factory.sol:setFeeToTreasury'](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L80)

```solidity

    function setFeeToTreasury(uint256 _minimumCollectibleFees) external {
        if (msg.sender != treasury) {
            revert GoatErrors.Forbidden();
        }
@->     minimumCollectableFees = _minimumCollectibleFees;
    }

```

If the Treasury  fee is set above `type(uint72).max` [GoatV1Pair.sol:_handleFee](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L693) function will break and the casting at will be done.

```solidity

    function _handleFees(uint256 amountWethIn, uint256 amountWethOut, bool isPresale)
        internal
        returns (uint256 feesCollected, uint256 feesLp)
    {
        ...

        pendingProtocolFees += feesCollected - feesLp;

        IGoatV1Factory _factory = IGoatV1Factory(factory);
@->     uint256 minCollectableFees = _factory.minimumCollectableFees();

@->     if (pendingProtocolFees > minCollectableFees) {
            IERC20(_weth).safeTransfer(_factory.treasury(), pendingProtocolFees);
            pendingProtocolFees = 0;
        }
@->     _pendingProtocolFees = uint72(pendingProtocolFees);
    }

```

For example ['GoatV1Factory.sol:setFeeToTreasury'](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L80) is set to `type(uint72).max + 10`. During a swap if `pendingProtocolFees > type(uint72).max + 1`, this `if (pendingProtocolFees > minCollectableFees)` condition will be false, and `pendingProtocolFees` will be cast to 1 instead of 4722366482869645213696 that is a lost of 4722366482869645213695 wei, or 4722.366482869645213695 ether.

## POC

paste the code snippet below into this file
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/test/foundry/periphery/GoatV1Router.t.sol#L1494

and run the command below

```bash
    forge test --mt testFeePOC -vvv
```

```sol

    function testFeePOC() public {
        
        _addLiquidityAndConvertToAmm(); // convert directly to amm

        uint swapAmount = 798000 ether;

        weth.deposit{value: swapAmount}();

        // set Tresury fee to 5000 ether
        factory.setFeeToTreasury(5000e18);

        GoatV1Pair pair = GoatV1Pair(factory.getPool(address(token)));
        weth.transfer(swapper, swapAmount); // send some weth to swapper
        vm.startPrank(swapper);
        weth.approve(address(router), swapAmount);
        uint256 amountOut = router.swapWethForExactTokens(
            swapAmount,
            0, // no slippage protection for now
            address(token),
            swapper,
            block.timestamp
        );
        vm.stopPrank();

        uint256 fees = (swapAmount * 99) / 10000; // 1% fee

        uint expectedFee = (fees * 60) / 100;
        uint actualFee = pair.getPendingProtocolFees();

        console2.log("Expected Protocol Fees: ", expectedFee);
        console2.log("Actual Protocol Fees:   ", actualFee);

        console2.log(actualFee > expectedFee);

    }

```

![Result](https://github.com/sherlock-audit/2024-03-goat-trading-joshuajee/assets/36106199/e5607115-2aca-485d-8447-44074bb583ef)


## Impact

Lose of funds for the Treasury, the impact would be felt more on chains like Polygon that has cheap native tokens, since `type(uint70).max` in Polygon is less than 5000 USD.

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L693
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L726

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L22

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L80

## Tool used

Manual Review

## Recommendation

To avoid this, make [_pendingProtocolFees:GoatV1Pair.sol](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L61) to be `uint256`  and the casting to `uint72` should be removed [_pendingProtocolFees:GoatV1Pair.sol](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L726).

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L61

```diff
+     uint256 private _pendingProtocolFees;
-     uint72 private _pendingProtocolFees;
```

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L726

```diff
+    _pendingProtocolFees = pendingProtocolFees;
-    _pendingProtocolFees = uint72(pendingProtocolFees);
```