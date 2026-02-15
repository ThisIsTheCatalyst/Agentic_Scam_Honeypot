def should_use_llm(strategy: str, agent_state: dict, session: dict) -> bool:

    turns = agent_state.get("turns", 0)
    llm_calls = agent_state.get("llm_calls", 0)
    confidence = session.get("scam_confidence", 0)

    MAX_CALLS = 12

    # -------------------------
    # Hard Cap
    # -------------------------
    if llm_calls >= MAX_CALLS:
        return False

    # -------------------------
    # Phase 1: Hook (first 2 turns)
    # -------------------------
    if turns <= 1:
        return True

    # -------------------------
    # High-value extraction always allowed
    # -------------------------
    high_value_strategies = {
        "extract_payment",
        "extract_identity",
        "extract_bank",
        "escalate_trust"
    }

    if strategy in high_value_strategies:
        return True

    # -------------------------
    # If scam likelihood is high,
    # increase realism moderately
    # -------------------------
    if confidence >= 4 and llm_calls < 9:
        return True

    # -------------------------
    # Light refresh every 6 turns
    # -------------------------
    if turns % 3 == 0 and llm_calls < 10:
        return True

    # -------------------------
    # Default fallback
    # -------------------------
    return False
