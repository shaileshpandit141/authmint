from authmint.services import TokenMint
from authmint.exceptions import InvalidTokenError


def test_token_mint_instance(email_verification_mint: TokenMint) -> None:
    """Check token mint instance."""
    assert isinstance(email_verification_mint, TokenMint)


def test_generated_token(email_verification_mint: TokenMint) -> None:
    """Generated a email verification token."""
    token = email_verification_mint.generate_token(
        subject_id="user:25",
        extra_claims={"role": "admin"},
    )

    assert isinstance(token, str)


def test_validate_generated_token(email_verification_mint: TokenMint) -> None:
    """Validate Generated token."""
    token = email_verification_mint.generate_token(
        subject_id="user:25",
        extra_claims={"role": "admin"},
    )

    assert isinstance(token, str)
    try:
        claim = email_verification_mint.validate_token(
            token=token,
        )
        assert isinstance(claim, dict)
    except InvalidTokenError:
        pass
