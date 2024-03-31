Keen Tawny Ant

high

# Some unusual problems arise in the use of the `GoatV1Factory.sol#createPair()` function.

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