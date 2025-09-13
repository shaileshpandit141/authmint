from datetime import timedelta
from tokenmint.services import TokenMint
from tokenmint.settings import Settings
from pytest import fixture
from dotenv import load_dotenv

# Load all env variables.
load_dotenv()


@fixture(scope="session")
def email_verification_mint() -> TokenMint:
    """Create token mint instance and return it."""
    return TokenMint(
        settings=Settings(
            issuer="mytest.service",
            audience="user",
            purpose="email-verification",
            expiry_duration=timedelta(minutes=5),
            prevent_replay=True,
        )
    )
