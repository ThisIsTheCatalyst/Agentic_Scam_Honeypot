def should_terminate(session, agent_state):
    turns = agent_state.get("turns", 0)
    stalls = agent_state.get("stall_count", 0)
    scam_detected = session.get("scam_detected", False)
    intelligence = session.get("intelligence", {})

    # Count meaningful intelligence
    intel_count = (
        len(intelligence.get("upiIds", [])) +
        len(intelligence.get("phishingLinks", [])) +
        len(intelligence.get("phoneNumbers", [])) +
        len(intelligence.get("bankAccounts", []))
    )

    # 1️⃣ Never terminate if scam not confirmed
    if not scam_detected:
        return False

    # 2️⃣ Force minimum engagement depth
    MIN_TURNS = 10
    if turns < MIN_TURNS:
        return False

    # 3️⃣ If we have extracted something meaningful, allow termination
    if intel_count >= 1:
        return True

    # 4️⃣ If stalled after enough turns
    if stalls >= 3:
        return True

    # 5️⃣ Absolute hard cap
    if turns >= 20:
        return True

    return False
