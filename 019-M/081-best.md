Keen Tawny Ant

medium

# An attacker can use the `swap` function to receive more tokens with a smaller amount of ETH.

## Summary
An attacker can receive more tokens with a smaller amount of ETH by directly calling the` GoatV1Pair.sol#swap` function.
Therefore, the protocol suffers a loss of funds.
## Vulnerability Detail
The `GoatV1Pair.sol#swap` function is as follows.

```solidity
    function swap(uint256 amountTokenOut, uint256 amountWethOut, address to) external nonReentrant {
        if (amountTokenOut == 0 && amountWethOut == 0) {
            revert GoatErrors.InsufficientOutputAmount();
        }
        if (amountTokenOut != 0 && amountWethOut != 0) {
            revert GoatErrors.MultipleOutputAmounts();
        }
        GoatTypes.LocalVariables_Swap memory swapVars;
        swapVars.isBuy = amountWethOut > 0 ? false : true;
        // check for mev
        _handleMevCheck(swapVars.isBuy);

        (swapVars.initialReserveEth, swapVars.initialReserveToken) = _getActualReserves();

        if (amountTokenOut > swapVars.initialReserveToken || amountWethOut > swapVars.initialReserveEth) {
            revert GoatErrors.InsufficientAmountOut();
        }

        if (swapVars.isBuy) {
            swapVars.amountWethIn = IERC20(_weth).balanceOf(address(this)) - swapVars.initialReserveEth
                - _pendingLiquidityFees - _pendingProtocolFees;
            // optimistically send tokens out
            IERC20(_token).safeTransfer(to, amountTokenOut);
        } else {
            swapVars.amountTokenIn = IERC20(_token).balanceOf(address(this)) - swapVars.initialReserveToken;
            // optimistically send weth out
            IERC20(_weth).safeTransfer(to, amountWethOut);
        }
        swapVars.vestingUntil = _vestingUntil;
        swapVars.isPresale = swapVars.vestingUntil == _MAX_UINT32;

        (swapVars.feesCollected, swapVars.lpFeesCollected) =
            _handleFees(swapVars.amountWethIn, amountWethOut, swapVars.isPresale);

        swapVars.tokenAmount = swapVars.isBuy ? amountTokenOut : swapVars.amountTokenIn;

        // We store details of participants so that we only allow users who have
        // swap back tokens who have bought in the vesting period.
        if (swapVars.vestingUntil > block.timestamp) {
            _updatePresale(to, swapVars.tokenAmount, swapVars.isBuy);
        }

        if (swapVars.isBuy) {
            swapVars.amountWethIn -= swapVars.feesCollected;
        } else {
            unchecked {
                amountWethOut += swapVars.feesCollected;
            }
        }
        swapVars.finalReserveEth = swapVars.isBuy
            ? swapVars.initialReserveEth + swapVars.amountWethIn
            : swapVars.initialReserveEth - amountWethOut;
        swapVars.finalReserveToken = swapVars.isBuy
            ? swapVars.initialReserveToken - amountTokenOut
            : swapVars.initialReserveToken + swapVars.amountTokenIn;

        swapVars.bootstrapEth = _bootstrapEth;
        // presale lp fees should go to reserve eth
        if (swapVars.isPresale && ((swapVars.finalReserveEth + swapVars.lpFeesCollected) > swapVars.bootstrapEth)) {
            // at this point pool should be changed to an AMM
            _checkAndConvertPool(swapVars.finalReserveEth + swapVars.lpFeesCollected, swapVars.finalReserveToken);
        } else {
            // check for K

            (swapVars.virtualEthReserveBefore, swapVars.virtualTokenReserveBefore) =
                _getReserves(swapVars.vestingUntil, swapVars.initialReserveEth, swapVars.initialReserveToken);
            (swapVars.virtualEthReserveAfter, swapVars.virtualTokenReserveAfter) =
                _getReserves(swapVars.vestingUntil, swapVars.finalReserveEth, swapVars.finalReserveToken);
            if (
                swapVars.virtualEthReserveBefore * swapVars.virtualTokenReserveBefore
                    > swapVars.virtualEthReserveAfter * swapVars.virtualTokenReserveAfter
            ) {
                revert GoatErrors.KInvariant();
            }
        }

        if (swapVars.isPresale) {
            swapVars.finalReserveEth += swapVars.lpFeesCollected;
        }
        _update(swapVars.finalReserveEth, swapVars.finalReserveToken, false);

        emit Swap(
            msg.sender,
            swapVars.amountWethIn + swapVars.feesCollected,
            swapVars.amountTokenIn,
            amountWethOut,
            amountTokenOut,
            to
        );
    }
```
As you can see on the right, if you set the parameters in the `GoatV1Pair.sol#swap` function to `amountTokenOut = a` and `amountWethOut = 0`, `swapVars.isBuy = true`. Also, before this, the attacker sends `b + swapVars.initialReserveEth+_pendingLiquidityFees + _pendingProtocolFees`wei directly to this contract.
At this time, since `swapVars.amountWethIn = b`, it continues to be executed in the `_handleFees` function.
Next, there is the conditional statement below.
```solidity
    (swapVars.virtualEthReserveBefore, swapVars.virtualTokenReserveBefore) =
        _getReserves(swapVars.vestingUntil, swapVars.initialReserveEth, swapVars.initialReserveToken);
    (swapVars.virtualEthReserveAfter, swapVars.virtualTokenReserveAfter) =
        _getReserves(swapVars.vestingUntil, swapVars.finalReserveEth, swapVars.finalReserveToken);
    if (
        swapVars.virtualEthReserveBefore * swapVars.virtualTokenReserveBefore
            > swapVars.virtualEthReserveAfter * swapVars.virtualTokenReserveAfter
    ) {
        revert GoatErrors.KInvariant();
    }
```
Here, the attacker carefully considers the quantity relationship to avoid reverting.
Let's look at a simple example.
`swapVars.virtualEthReserveBefore = 60`, `swapVars.virtualTokenReserveBefore = 30` and `a = 5`, `b = 5`.
Since `(60 * 30 <= 55 * 35)`, it is not reverted.
## Impact
The attacker determines the exact quantity relationship and profits from it.
Therefore, the protocol suffers a loss of funds.
Since this is easily possible, I mark it as medium.
## Code Snippet
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L242-L331
## Tool used

Manual Review

## Recommendation
There are several ways, but the simplest way is to prevent the `swap` function from being called directly from outside.