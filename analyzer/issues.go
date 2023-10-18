package analyzer

// AllIssues returns the list of all issues.
func AllIssues() []Issue {
	return append(append(append(GasOpIssues(), LowRiskIssues()...), MediumRiskIssues()...), HighRiskIssues()...)
	// return append(GasOpIssues(), LowRiskIssues(), MediumRiskIssues(), HighRiskIssues()...)
}

// GasOpIssues returns the list of all gas optimization issues.
func GasOpIssues() []Issue {
	return []Issue{
		// G001 - Don't Initialize Variables with Default Value
		{
			"G001",
			GASOP,
			"Don't Initialize Variables with Default Value",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/0-Gas-Optimizations.md#g001---dont-initialize-variables-with-default-value",
			`(uint[0-9]*[[:blank:]][a-z,A-Z,0-9]*.?=.?0;)|(bool.[a-z,A-Z,0-9]*.?=.?false;)`,
		},
		// G002 - Cache Array Length Outside of Loop
		{
			"G002",
			GASOP,
			"Cache Array Length Outside of Loop",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/0-Gas-Optimizations.md#g002---cache-array-length-outside-of-loop",
			".length",
		},
		// G003 - Use != 0 instead of > 0 for Unsigned Integer Comparison
		{
			"G003",
			GASOP,
			"Use != 0 instead of > 0 for Unsigned Integer Comparison",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/0-Gas-Optimizations.md#g003---use--0-instead-of--0-for-unsigned-integer-comparison",
			"(>0|> 0)",
		},
		// G006 - Use immutable for OpenZeppelin AccessControl's Roles Declarations
		{
			"G006",
			GASOP,
			"Use immutable for OpenZeppelin AccessControl's Roles Declarations",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/0-Gas-Optimizations.md#g006---use-immutable-for-openzeppelin-accesscontrols-roles-declarations",
			"keccak",
		},
		// G007 - Long Revert Strings
		{
			"G007",
			GASOP,
			"Long Revert Strings",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/0-Gas-Optimizations.md#g007---long-revert-strings",
			"\".{33,}\"", // Anything between "'s with at least 33 characters
		},
		// G008 - Use Shift Right/Left instead of Division/Multiplication if possible
		{
			"G008",
			GASOP,
			"Use Shift Right/Left instead of Division/Multiplication if possible",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/0-Gas-Optimizations.md#g008---use-shift-rightleft-instead-of-divisionmultiplication-if-possible",
			`(/[2,4,8]|/ [2,4,8]|\*[2,4,8]|\* [2,4,8])`,
		},
	}
}

// LowRiskIssues returns the list of all low risk issues.
func LowRiskIssues() []Issue {
	return []Issue{
		// L001 - Unsafe ERC20 Operation(s)
		{
			"L001",
			LOW,
			"Unsafe ERC20 Operation(s)",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/2-Low-Risk.md#l001---unsafe-erc20-operations",
			`\.transfer\(|\.transferFrom\(|\.approve\(`, // ".tranfer(", ".transferFrom(" or ".approve("
		},
		// L003 - Unspecific Compiler Version Pragma
		{
			"L003",
			LOW,
			"Unspecific Compiler Version Pragma",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/2-Low-Risk.md#l003---unspecific-compiler-version-pragma",
			"pragma solidity (\\^|>)", // "pragma solidity ^" or "pragma solidity >"
		},
		// L005 - Do not use Deprecated Library Functions
		{
			"L005",
			LOW,
			"Do not use Deprecated Library Functions",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/2-Low-Risk.md#l005---do-not-use-deprecated-library-functions",
			`_setupRole\(|safeApprove\(`, // _setupRole and safeApprove are common deprecated lib functions
		},
	}
}

// HighRiskIssues returns the list of all high risk issues.
func HighRiskIssues() []Issue {
	return []Issue{
		// H001 - Unsafe ERC20 Operation(s)
		{
			"H001",
			HIGH,
			"Unsafe ERC20 Operation(s)",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h001---unsafe-erc20-operations",
			`\.transfer\(|\.transferFrom\(|\.approve\(`,
		},
		// H002 - Loans can be rolled an unlimited number of times
		{
			"H002",
			HIGH,
			"Loans can be rolled an unlimited number of times",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h002---loans-can-be-rolled-an-unlimited-number-of-times",
			"toggleRoll() can't be used to stop rolls if they're all done in a single transaction.", // "pragma solidity ^" or "pragma solidity >"
		},
		// H003 - Fully repaying a loan will result in debt payment being lost
		{
			"H003",
			HIGH,
			"Fully repaying a loan will result in debt payment being lost",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h003---fully-repaying-a-loan-will-result-in-debt-payment-being-lost",
			`_loan\(|loan.lender\Cooler#repay(`,
		},
		// H004 - Lender force Loan become default
		{
			"H004",
			HIGH,
			"Lender force Loan become default",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h004---lender-force-loan-become-default",
			`repay()`,
		},
		// H005 - StakedCitadel depositors can be attacked by the first depositor with depressing of vault token denomination
		{
			"H005",
			HIGH,
			"StakedCitadel depositors can be attacked by the first depositor with depressing of vault token denomination",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h005---stakedcitadel-depositors-can-be-attacked-by-the-first-depositor-with-depressing-of-vault-token-denomination",
			`require(_controller != address(`,
		},
		// H006 - Truncation in OrderValidator can lead to resetting the fill and selling more tokens
		{
			"H006",
			HIGH,
			"Truncation in OrderValidator can lead to resetting the fill and selling more tokens",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h006---truncation-in-ordervalidator-can-lead-to-resetting-the-fill-and-selling-more-tokens",
			` require(numerator <= type(`,
		},
		// H007 - yVault: First depositor can break minting of shares
		{
			"H007",
			HIGH,
			"yVault: First depositor can break minting of shares",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h007---yvault-first-depositor-can-break-minting-of-shares",
			`require(_shares != 0, "zero shares minted");`,
		},
		// H008 - Reentrancy issue in yVault.deposit
		{
			"H008",
			HIGH,
			"Reentrancy issue in yVault.deposit",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h008---reentrancy-issue-in-yvaultdeposit",
			`The safeTransferFrom should be the last call in deposit.`,
		},
		// H009 - Setting new controller can break YVaultLPFarming
		{
			"H009",
			HIGH,
			"Setting new controller can break YVaultLPFarming",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h009---setting-new-controller-can-break-yvaultlpfarming",
			`require(_controller != address(0), "INVALID_CONTROLLER");`,
		},
		// H010 - Can force borrower to pay huge interest
		{
			"H010",
			HIGH,
			"Can force borrower to pay huge interest",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h010---can-force-borrower-to-pay-huge-interest",
			`The loan amount should not have min amount semantics.`,
		},
		// H011 - Oracle price does not compound
		{
			"H011",
			HIGH,
			"Oracle price does not compound",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h011---oracle-price-does-not-compound",
			`Calling getCurrentOraclePrice() now would return 1.0 again as timeDelta (and priceDelta) is zero: oraclePriceInt + priceDelta = oraclePriceInt = 1.0.`,
		},
		// H012 - Withdrawal delay can be circumvented
		{
			"H012",
			HIGH,
			"Withdrawal delay can be circumvented",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h012---withdrawal-delay-can-be-circumvented",
			`it.only("will cause 0 share issuance", async () => {`,
		},
		// H013 - First depositor can break minting of shares
		{
			"H013",
			HIGH,
			"First depositor can break minting of shares",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h013---first-depositor-can-break-minting-of-shares",
			`it("will cause 0 share issuance", async () => {`,
		},
		// H014 - Can deposit native token for free and steal funds
		{
			"H014",
			HIGH,
			"Can deposit native token for free and steal funds",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h014---can-deposit-native-token-for-free-and-steal-funds",
			`Check tokenAddress != NATIVE in depositErc20.`,
		},
		// H015 - WWrong formula when add fee incentivePool can lead to loss of funds
		{
			"H015",
			HIGH,
			"WWrong formula when add fee incentivePool can lead to loss of funds",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h015---wwrong-formula-when-add-fee-incentivepool-can-lead-to-loss-of-funds",
			`incentivePool[tokenAddress] += (amount * (transferFeePerc - tokenManager.getTokensInfo(tokenAddress).equilibriumFee)) / BASE_DIVISOR;`,
		},
		// H016 - Spend limit on owner can be bypassed
		{
			"H016",
			HIGH,
			"Spend limit on owner can be bypassed",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h016---spend-limit-on-owner-can-be-bypassed",
			`After successful spend, the config.spend_limit should be decreased by the amount spend`,
		},
		// H017 - Reentrancy in MessageProxyForSchain leads to replay attacks
		{
			"H017",
			HIGH,
			"Reentrancy in MessageProxyForSchain leads to replay attacks",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h017---reentrancy-in-messageproxyforschain-leads-to-replay-attacks",
			`for (uint256 i = 0; i < messages.length; i++) {`,
		},
	}
}

// MediumRiskIssues returns the list of all medium risk issues.
func MediumRiskIssues() []Issue {
	return []Issue{
		// M001 - Cooler.roll() wouldn't work as expected when newCollateral = 0

		{
			"M001",
			MEDIUM,
			"Cooler.roll() wouldn't work as expected when newCollateral = 0",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/3-High-Risk.md#h007---setting-new-controller-can-break-yvaultlpfarming",
			`roll()/newCollateral = 0/newCollateral = 0./req.duration`,
		},
		// M002 - Loan is rollable by default
		{
			"M002",
			MEDIUM,
			"Loan is rollable by default",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/4-Medium-Risk.md#m002---loan-is-rollable-by-default",
			"rollable",
		},
		// H003 - Repaying loans with small amounts of debt tokens can lead to underflowing in the roll function
		{
			"M003",
			MEDIUM,
			"Repaying loans with small amounts of debt tokens can lead to underflowing in the roll function",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/4-Medium-Risk.md#m003---repaying-loans-with-small-amounts-of-debt-tokens-can-lead-to-underflowing-in-the-roll-function",
			`roll/newCollateral/repay`,
		},
		// M004 - Dust amounts can cause payments to fail, leading to default
		{
			"M004",
			MEDIUM,
			"Dust amounts can cause payments to fail, leading to default",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/4-Medium-Risk.md#m004---dust-amounts-can-cause-payments-to-fail-leading-to-default",
			`loan.amount -= repai`,
		},
		// M005 - DAI/gOHM exchange rate may be stale
		{
			"M005",
			MEDIUM,
			"DAI/gOHM exchange rate may be stale",
			"https://github.com/danMendes-bossanova/c4-common-issuesd/blob/main/4-Medium-Risk.md#m005---daigohm-exchange-rate-may-be-stale",
			`maxLTC`,
		},
	}
}
