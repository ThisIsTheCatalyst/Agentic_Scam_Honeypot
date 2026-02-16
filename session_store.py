import json
import logging
from redis.exceptions import RedisError
from redis_client import redis_client

SESSION_TTL_SECONDS = 3600  

logger = logging.getLogger(__name__)



def get_session(session_id: str) -> dict:
    key = f"session:{session_id}"

    try:
        raw = redis_client.get(key)
    except RedisError as e:
        logger.error("Redis GET failed: %s", e)
        raw = None 

    if raw:
        return json.loads(raw)

    
    session = {
        "messages": [],
        "agent_state": {
            "turns": 0,
            "stall_count": 0,
            "current_strategy": "delay",
            "last_language": "english",
            "used_templates": [],
            "llm_calls": 0
        },
        "intelligence": {
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": []
        },
        "scam_detected": True,
        "finalized": False
    }

    try:
        redis_client.setex(
            key,
            SESSION_TTL_SECONDS,
            json.dumps(session)
        )
    except RedisError as e:
        logger.error("Redis SET failed: %s", e)

    return session



def save_session(session_id: str, session: dict) -> None:
    key = f"session:{session_id}"

    try:
        redis_client.setex(
            key,
            SESSION_TTL_SECONDS,
            json.dumps(session)
        )
    except RedisError as e:
        logger.error("Redis SET failed: %s", e)
