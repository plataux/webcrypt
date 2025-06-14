from webcrypt.jose import JOSE, Token, CLOCK_SKEW_SECONDS
import webcrypt.exceptions as tex

import pytest
import time


# Helper for consistent timestamp generation
def get_current_ts():
    return int(time.time())


def test_time_based_claims_exp():
    jose = JOSE()
    pub_jose = JOSE.from_jwks(jose.public_jwks())

    # --- Scenario 1: Token is valid (initial state) ---
    # Create a token that expires well into the future, say 10 minutes from now.
    # This ensures it's valid for our immediate checks.
    tk_valid_future = Token(exp=get_current_ts() + 600)  # Valid for 10 mins
    jwt_valid_future = jose.sign(tk_valid_future)
    assert pub_jose.verify(jwt_valid_future), "Token should be valid when created far in future"

    # --- Scenario 2: Token *just* expired, but within CLOCK_SKEW_SECONDS window ---
    # Create a token that expires slightly *before* current_ts + CLOCK_SKEW_SECONDS.
    # E.g., if now_ts = 100, CLOCK_SKEW = 60, then token.exp = 100 - 30 = 70.
    # Our rule: now_ts (100) > token.exp (70) + CLOCK_SKEW (60) => 100 > 130 (False) -> Should be VALID
    tk_exp_within_skew = Token(exp=get_current_ts() - (CLOCK_SKEW_SECONDS // 2))  # Expires 30s ago if skew is 60s
    jwt_exp_within_skew = jose.sign(tk_exp_within_skew)
    assert pub_jose.verify(jwt_exp_within_skew), "Token should be valid if expired within clock skew"

    # --- Scenario 3: Token definitively expired (outside CLOCK_SKEW_SECONDS window) ---
    # Create a token that expired well before (current_ts - CLOCK_SKEW_SECONDS).
    # E.g., if now_ts = 100, CLOCK_SKEW = 60, then token.exp = 100 - 60 - 1 = 39.
    # Our rule: now_ts (100) > token.exp (39) + CLOCK_SKEW (60) => 100 > 99 (True) -> Should be EXPIRED
    tk_definitely_expired = Token(exp=get_current_ts() - (CLOCK_SKEW_SECONDS + 10))  # Expires 70s ago if skew is 60s
    jwt_definitely_expired = jose.sign(tk_definitely_expired)
    with pytest.raises(tex.ExpiredSignature, match="Token has expired"):
        pub_jose.verify(jwt_definitely_expired)

    # --- Scenario 4: Token expires exactly at current_ts, should be valid with skew ---
    tk_exp_at_now = Token(exp=get_current_ts())
    jwt_exp_at_now = jose.sign(tk_exp_at_now)
    assert pub_jose.verify(jwt_exp_at_now), "Token expiring exactly now should be valid due to skew"

    # --- Scenario 5: Token expires CLOCK_SKEW_SECONDS ago, should still be valid ---
    tk_exp_at_skew = Token(exp=get_current_ts() - CLOCK_SKEW_SECONDS)
    jwt_exp_at_skew = jose.sign(tk_exp_at_skew)
    assert pub_jose.verify(jwt_exp_at_skew), "Token expiring exactly at skew boundary should be valid"

    # --- Scenario 6: Token expires CLOCK_SKEW_SECONDS + 1 ago, should be expired ---
    tk_exp_just_past_skew = Token(exp=get_current_ts() - (CLOCK_SKEW_SECONDS + 1))
    jwt_exp_just_past_skew = jose.sign(tk_exp_just_past_skew)
    with pytest.raises(tex.ExpiredSignature):
        pub_jose.verify(jwt_exp_just_past_skew)


def test_time_based_claims_iat():
    jose = JOSE()
    pub_jose = JOSE.from_jwks(jose.public_jwks())

    # Recall our iat validation rule: `if now_ts + CLOCK_SKEW_SECONDS < token.iat:`

    # Scenario 1: `iat` in the distant past (should be valid)
    tk_iat_past = Token(iat=get_current_ts() - 3600)  # Issued 1 hour ago
    jwt_iat_past = jose.sign(tk_iat_past)
    assert pub_jose.verify(jwt_iat_past), "Token with iat in the distant past should be valid"

    # Scenario 2: `iat` at current_ts (should be valid)
    # now_ts (100) + skew (60) < iat (100) => 160 < 100 (False) -> Valid
    tk_iat_at_now = Token(iat=get_current_ts())
    jwt_iat_at_now = jose.sign(tk_iat_at_now)
    assert pub_jose.verify(jwt_iat_at_now), "Token with iat exactly at current time should be valid"

    # Scenario 3: `iat` in the future, *within* CLOCK_SKEW_SECONDS window (should be valid)
    # now_ts (100) + skew (60) < iat (100 + 59) => 160 < 159 (False) -> Valid
    tk_iat_within_skew = Token(iat=get_current_ts() + CLOCK_SKEW_SECONDS - 1)
    jwt_iat_within_skew = jose.sign(tk_iat_within_skew)
    assert pub_jose.verify(jwt_iat_within_skew), \
        "Token with iat just within skew window should be valid"

    # Scenario 4: `iat` exactly at CLOCK_SKEW_SECONDS in the future (should be valid)
    # now_ts (100) + skew (60) < iat (100 + 60) => 160 < 160 (False) -> Valid
    tk_iat_at_skew_boundary_future = Token(iat=get_current_ts() + CLOCK_SKEW_SECONDS)
    jwt_iat_at_skew_boundary_future = jose.sign(tk_iat_at_skew_boundary_future)
    assert pub_jose.verify(jwt_iat_at_skew_boundary_future), \
        "Token with iat exactly at skew boundary in future should be valid"

    # Scenario 5: `iat` *beyond* CLOCK_SKEW_SECONDS in the future (should raise InvalidClaims)
    # now_ts (100) + skew (60) < iat (100 + 60 + 1) => 160 < 161 (True) -> InvalidClaims
    tk_iat_beyond_skew = Token(iat=get_current_ts() + CLOCK_SKEW_SECONDS + 1)
    jwt_iat_beyond_skew = jose.sign(tk_iat_beyond_skew)
    with pytest.raises(tex.InvalidClaims, match=r"iat claim cannot be in the future: \d+ vs \d+"):  # Corrected regex
        pub_jose.verify(jwt_iat_beyond_skew)


# --- nbf (Not Before) Claims Tests ---

def test_time_based_claims_nbf():
    jose = JOSE()
    pub_jose = JOSE.from_jwks(jose.public_jwks())

    # Recall our nbf validation rule: `if now_ts < token.nbf - CLOCK_SKEW_SECONDS:`

    # Scenario 1: `nbf` in the distant past (should be valid)
    tk_nbf_past = Token(nbf=get_current_ts() - 3600)  # Valid 1 hour ago
    jwt_nbf_past = jose.sign(tk_nbf_past)
    assert pub_jose.verify(jwt_nbf_past), "Token with nbf in the distant past should be valid"

    # Scenario 2: `nbf` at current_ts (should be valid)
    # now_ts (100) < nbf (100) - skew (60) => 100 < 40 (False) -> Valid
    tk_nbf_at_now = Token(nbf=get_current_ts())
    jwt_nbf_at_now = jose.sign(tk_nbf_at_now)
    assert pub_jose.verify(jwt_nbf_at_now), "Token with nbf exactly at current time should be valid"

    # Scenario 3: `nbf` in the future, *within* CLOCK_SKEW_SECONDS window (should be valid)
    # now_ts (100) < nbf (100 + 59) - skew (60) => 100 < 99 (False) -> Valid
    tk_nbf_within_skew = Token(nbf=get_current_ts() + CLOCK_SKEW_SECONDS - 1)
    jwt_nbf_within_skew = jose.sign(tk_nbf_within_skew)
    assert pub_jose.verify(jwt_nbf_within_skew), \
        "Token with nbf just within skew window should be valid"

    # Scenario 4: `nbf` exactly at CLOCK_SKEW_SECONDS in the future (should be valid)
    # now_ts (100) < nbf (100 + 60) - skew (60) => 100 < 100 (False) -> Valid
    tk_nbf_at_skew_boundary_future = Token(nbf=get_current_ts() + CLOCK_SKEW_SECONDS)
    jwt_nbf_at_skew_boundary_future = jose.sign(tk_nbf_at_skew_boundary_future)
    assert pub_jose.verify(jwt_nbf_at_skew_boundary_future), \
        "Token with nbf exactly at skew boundary in future should be valid"

    # Scenario 5: `nbf` *beyond* CLOCK_SKEW_SECONDS in the future (should raise NotYetValid)
    # now_ts (100) < nbf (100 + 60 + 1) - skew (60) => 100 < 101 (True) -> NotYetValid
    tk_nbf_beyond_skew = Token(nbf=get_current_ts() + CLOCK_SKEW_SECONDS + 1)
    jwt_nbf_beyond_skew = jose.sign(tk_nbf_beyond_skew)
    # Corrected: This scenario *should* raise NotYetValid, and the regex updated
    with pytest.raises(tex.NotYetValid,
                       match=r"Token isn't valid yet: nbf \d+ hasn't been reached within allowed clock skew \d+s \(current: \d+\)"):
        pub_jose.verify(jwt_nbf_beyond_skew)
