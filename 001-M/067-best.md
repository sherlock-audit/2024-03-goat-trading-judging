Daring Champagne Scallop

high

# The router is not compatible with fee on transfers tokens

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
