Fierce Foggy Pike

high

# GoatV1Pair Mint Function Vulnerability:Initial LP Balance Impersonation Risk

## Summary
In `GoatV1Pair::mint()` function allows for an impersonation attack where the attacker, by minting liquidity as the initial liquidity provider, can improperly influence the initial LP's fractional balance
## Vulnerability Detail
This comes from the improper update of the initial LP's fractional balance in the `mint` function. When new liquidity is minted, the function fails to properly validate whether the caller is indeed the initial LP or an impersonator. This allows an attacker to mint liquidity in the name of the initial LP, which leads to an unwarranted increase in the initial LP's fractional balance.
## Impact
This is manipulation of liquidity pool parameters. An attacker could exploit this to inflate the fractional balance of the initial LP and this could be used to withdraw more assets than entitled.

## Code Snippet

The issue is found here 

https://github.com/sherlock-audit/2024-03-goat-trading/blob/main/goat-trading/contracts/exchange/GoatV1Pair.sol#L160

Here is the POC

```solidity
function testInitialLpInfoUpdate() public {
    GoatTypes.InitParams memory initParams;
    initParams.bootstrapEth = 10e18;
    initParams.virtualEth = 10e18;
    initParams.initialEth = 10e18;
    initParams.initialTokenMatch = 1000e18;

    _mintInitialLiquidity(initParams, users.lp);

    // Ensure the initial LP's information is correctly set
    GoatTypes.InitialLPInfo memory initialLpInfoBefore = pair.getInitialLPInfo();
    console.log("Initial LP Address Before:", address(initialLpInfoBefore.liquidityProvider)); // Logging address
    console.log("Initial LP Fractional Balance Before:", initialLpInfoBefore.fractionalBalance); // Logging fractional balance

    // Attempt to mint liquidity by another user
    _mintLiquidity(10e18, 1000e18, users.bob);

    // Check if the initial LP's information is still the same
    GoatTypes.InitialLPInfo memory initialLpInfoAfter = pair.getInitialLPInfo();   
    console2.log("Initial LP Address After Other User Mint:", address(initialLpInfoAfter.liquidityProvider));
    console.log("Initial LP Fractional Balance After Other User Mint:", initialLpInfoAfter.fractionalBalance);

    // Impersonate the initial LP and mint liquidity
    _mintLiquidity(5e18, 500e18, users.lp);

    // Verify the initial LP's information after impersonation
    GoatTypes.InitialLPInfo memory initialLpInfoAfterImpersonation = pair.getInitialLPInfo();
    console2.log("Initial LP Address After Impersonation:", address(initialLpInfoAfterImpersonation.liquidityProvider));
    console2.log("Initial LP Fractional Balance After Impersonation:", initialLpInfoAfterImpersonation.fractionalBalance);

    // Assertions remain the same
    assertEq(initialLpInfoAfterImpersonation.liquidityProvider, users.lp, "Initial LP's address should remain the same after impersonation attempt");
    assertEq(initialLpInfoAfterImpersonation.fractionalBalance, initialLpInfoBefore.fractionalBalance, "Initial LP's fractional balance should remain unchanged after impersonation attempt");
}
```

Here is the results from the test
```solidity
Logs:
  Initial LP Address Before: 0x44bC268D6f10DfB004c5b9afe91648b1c7c8b6D9
  Initial LP Fractional Balance Before: 12499999999999999750
  Initial LP Address After Other User Mint: 0x44bC268D6f10DfB004c5b9afe91648b1c7c8b6D9
  Initial LP Fractional Balance After Other User Mint: 12499999999999999750
  Initial LP Address After Impersonation: 0x44bC268D6f10DfB004c5b9afe91648b1c7c8b6D9
  Initial LP Fractional Balance After Impersonation: 18749999999999999750
  Error: Initial LP's fractional balance should remain unchanged after impersonation attempt
  Error: a == b not satisfied [uint]
    Expected: 12499999999999999750
      Actual: 18749999999999999750
```
## Tool used

Manual Review

## Recommendation
Use a modifier to check the role or use signatures to verify.