Agreeable Aquamarine Dog

high

# Reentrancy in `GoatPairV1::burn` if token is a non-standard ERC20

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