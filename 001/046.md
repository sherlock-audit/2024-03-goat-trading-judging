Great Grape Ram

high

# Legitimate pools can be taken over and the penalty is not fair.

## Summary

In [GoatV1Pair.takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L453-L538), a malicious user can take over pool from a legitimate user, because the mechanism for identifying is incorrect.  And the penalty mechanism is not fair.

## Vulnerability Detail

[GoatV1Pair.takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L453-L538) function exists to avoid grief, because only one pool can be created for each token.
Doc says "They can then lower the amount of virtual Ether or Ether to be raised, but not make it higher." about [GoatV1Pair.takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L453-L538). However, there is no checking for the amount of virtual Ether. This made it possible that legitimate pools can be taken over by malicious users.

L481 and L496 checks the amount of tokens, but there is no check for virtual Ether or Ether to be raised.
So, a malicious user can take over a legitimate pool without any cost. He can remove his cost by increasing the amount of virtual Ether or reserved Ether. Paying +10 percent token can do nothing with it. Furthermore, the old liquidity provider should pay 5% penalty. This is very unfair. Generally, a malicious user have no Ether reserved. So, it is only harmful to legitimate users.

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L453-L538

```javascript

    function takeOverPool(GoatTypes.InitParams memory initParams) external {
        if (_vestingUntil != _MAX_UINT32) {
            revert GoatErrors.ActionNotAllowed();
        }

        GoatTypes.InitialLPInfo memory initialLpInfo = _initialLPInfo;

        GoatTypes.LocalVariables_TakeOverPool memory localVars;
        address to = msg.sender;
        localVars.virtualEthOld = _virtualEth;
        localVars.bootstrapEthOld = _bootstrapEth;
        localVars.initialTokenMatchOld = _initialTokenMatch;

        (localVars.tokenAmountForPresaleOld, localVars.tokenAmountForAmmOld) = _tokenAmountsForLiquidityBootstrap(
            localVars.virtualEthOld,
            localVars.bootstrapEthOld,
            initialLpInfo.initialWethAdded,
            localVars.initialTokenMatchOld
        );

        // new token amount for bootstrap if no swaps would have occured
        (localVars.tokenAmountForPresaleNew, localVars.tokenAmountForAmmNew) = _tokenAmountsForLiquidityBootstrap(
            initParams.virtualEth, initParams.bootstrapEth, initParams.initialEth, initParams.initialTokenMatch
        );

        // team needs to add min 10% more tokens than the initial lp to take over
        localVars.minTokenNeeded =
            ((localVars.tokenAmountForPresaleOld + localVars.tokenAmountForAmmOld) * 11000) / 10000;

481     if ((localVars.tokenAmountForAmmNew + localVars.tokenAmountForPresaleNew) < localVars.minTokenNeeded) {
            revert GoatErrors.InsufficientTakeoverTokenAmount();
        }

        localVars.reserveEth = _reserveEth;

        // Actual token amounts needed if the reserves have updated after initial lp mint
        (localVars.tokenAmountForPresaleNew, localVars.tokenAmountForAmmNew) = _tokenAmountsForLiquidityBootstrap(
            initParams.virtualEth, initParams.bootstrapEth, localVars.reserveEth, initParams.initialTokenMatch
        );
        localVars.reserveToken = _reserveToken;

        // amount of tokens transferred by the new team
        uint256 tokenAmountIn = IERC20(_token).balanceOf(address(this)) - localVars.reserveToken;

        if (
496          tokenAmountIn
497             < (
498                 localVars.tokenAmountForPresaleOld + localVars.tokenAmountForAmmOld - localVars.reserveToken
499                     + localVars.tokenAmountForPresaleNew + localVars.tokenAmountForAmmNew
500             )
        ) {
            revert GoatErrors.IncorrectTokenAmount();
        }

        localVars.pendingLiquidityFees = _pendingLiquidityFees;
        localVars.pendingProtocolFees = _pendingProtocolFees;

        // amount of weth transferred by the new team
        uint256 wethAmountIn = IERC20(_weth).balanceOf(address(this)) - localVars.reserveEth
            - localVars.pendingLiquidityFees - localVars.pendingProtocolFees;

        if (wethAmountIn < localVars.reserveEth) {
            revert GoatErrors.IncorrectWethAmount();
        }

        _handleTakeoverTransfers(
            IERC20(_weth), IERC20(_token), initialLpInfo.liquidityProvider, localVars.reserveEth, localVars.reserveToken
        );

        uint256 lpBalance = balanceOf(initialLpInfo.liquidityProvider);
        _burn(initialLpInfo.liquidityProvider, lpBalance);

        // new lp balance
        lpBalance = Math.sqrt(uint256(initParams.virtualEth) * initParams.initialTokenMatch) - MINIMUM_LIQUIDITY;
        _mint(to, lpBalance);

        _updateStateAfterTakeover(
            initParams.virtualEth,
            initParams.bootstrapEth,
            initParams.initialTokenMatch,
            wethAmountIn,
            tokenAmountIn,
            lpBalance,
            to,
            initParams.initialEth
        );
    }
```

## Impact

Legitimate pools can be taken over unfairly.

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L453-L538

## Tool used

Manual Review

## Recommendation

I think that the mechanism for identifying should be improved. 
