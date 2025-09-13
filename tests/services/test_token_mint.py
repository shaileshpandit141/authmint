from tokenmint.services import TokenMint
from pytest import raises
from tokenmint.exceptions import InvalidTokenError


def test_token_mint_instance(email_verification_mint: TokenMint) -> None:
    """Check token mint instance."""
    assert isinstance(email_verification_mint, TokenMint)


def test_generated_token(email_verification_mint: TokenMint) -> None:
    """Generated a email verification token."""
    token = email_verification_mint.generate_token(
        subject="user@gmail.com",
        extra_claims={"role": "admin"},
    )

    assert isinstance(token, str)


def test_validate_valid_token(email_verification_mint: TokenMint) -> None:
    """Validate Generated token."""
    token = email_verification_mint.generate_token(
        subject="user@gmail.com",
        extra_claims={"role": "admin"},
    )

    claims = email_verification_mint.validate_token(token=token)

    assert isinstance(claims, dict)
    assert claims["sub"] == "user@gmail.com"
    assert claims["ext"]["role"] == "admin"


def test_validate_invalid_token(email_verification_mint: TokenMint) -> None:
    """Validate Generated token."""
    token = email_verification_mint.generate_token(
        subject="user@gmail.com",
        extra_claims={"role": "admin"},
    )

    email_verification_mint.revoke_token(token=token)

    with raises(InvalidTokenError):
        email_verification_mint.validate_token(token=token)
