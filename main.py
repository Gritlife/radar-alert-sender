import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pytz
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# Firestore (state)
from google.cloud import firestore

# Optional: Twilio for SMS alerts
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None


# =========================
# CONFIG
# =========================
TZ_NAME = os.getenv("MTS_TIMEZONE", "America/Chicago")  # CST/CDT handled by tz database
TZ = pytz.timezone(TZ_NAME)

PROJECT_ID = os.getenv("GCP_PROJECT", "")
ENV = os.getenv("ENV", "prod")

# MS operational window (doc): 3:00 AM – 7:00 PM CST (M–F) :contentReference[oaicite:6]{index=6}
MS_START_HHMM = os.getenv("MS_START_HHMM", "03:00")
MS_END_HHMM = os.getenv("MS_END_HHMM", "19:00")

# Alert attack window (doc): 8:45 AM CST – stop new attacks 3:00 PM CST :contentReference[oaicite:7]{index=7}
ATTACK_START_HHMM = os.getenv("ATTACK_START_HHMM", "08:45")
ATTACK_END_HHMM = os.getenv("ATTACK_END_HHMM", "15:00")

# User governance limit: max 3 options trades per session :contentReference[oaicite:8]{index=8}
MAX_TRADES_PER_SESSION = int(os.getenv("MAX_TRADES_PER_SESSION", "3"))

# Firestore collections
COL_TARGETS = os.getenv("COL_TARGETS", "mts_targets")
COL_ACTIVE = os.getenv("COL_ACTIVE", "mts_active")
COL_USERS = os.getenv("COL_USERS", "mts_users")
COL_EVENTS = os.getenv("COL_EVENTS", "mts_events")

# Strategy thresholds (placeholders; tune later)
MIN_MS_SCORE = float(os.getenv("MIN_MS_SCORE", "70"))
MIN_MCS_SCORE = float(os.getenv("MIN_MCS_SCORE", "75"))

# Twilio (optional)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")
ALERT_TO_NUMBER = os.getenv("ALERT_TO_NUMBER", "")  # single recipient; expand to user list later

logger = logging.getLogger("mts")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# =========================
# UTILS
# =========================
def now_ct() -> datetime:
    return datetime.now(TZ)

def parse_hhmm(hhmm: str) -> Tuple[int, int]:
    hh, mm = hhmm.split(":")
    return int(hh), int(mm)

def in_window(dt: datetime, start_hhmm: str, end_hhmm: str) -> bool:
    sh, sm = parse_hhmm(start_hhmm)
    eh, em = parse_hhmm(end_hhmm)
    start = dt.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end = dt.replace(hour=eh, minute=em, second=0, microsecond=0)
    return start <= dt <= end

def is_weekday(dt: datetime) -> bool:
    return dt.weekday() < 5

def event_id() -> str:
    return uuid.uuid4().hex

def safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


# =========================
# STATE (Firestore)
# =========================
db = firestore.Client()

def log_event(kind: str, payload: Dict[str, Any]) -> None:
    try:
        db.collection(COL_EVENTS).document(event_id()).set({
            "ts": firestore.SERVER_TIMESTAMP,
            "kind": kind,
            "env": ENV,
            "payload": payload,
        })
    except Exception as e:
        logger.warning(f"Failed to log event: {e}")

def upsert_target(ticker: str, doc: Dict[str, Any]) -> None:
    db.collection(COL_TARGETS).document(ticker).set(doc, merge=True)

def get_target(ticker: str) -> Optional[Dict[str, Any]]:
    snap = db.collection(COL_TARGETS).document(ticker).get()
    return snap.to_dict() if snap.exists else None

def list_targets(limit: int = 200) -> List[Dict[str, Any]]:
    snaps = db.collection(COL_TARGETS).limit(limit).stream()
    out = []
    for s in snaps:
        d = s.to_dict()
        d["_id"] = s.id
        out.append(d)
    return out

def set_active(ticker: str, doc: Dict[str, Any]) -> None:
    db.collection(COL_ACTIVE).document(ticker).set(doc, merge=True)

def get_active(ticker: str) -> Optional[Dict[str, Any]]:
    snap = db.collection(COL_ACTIVE).document(ticker).get()
    return snap.to_dict() if snap.exists else None

def remove_active(ticker: str) -> None:
    db.collection(COL_ACTIVE).document(ticker).delete()

def increment_user_trade(user_id: str, session_key: str) -> int:
    """
    Increments user's trade count for a session key, returns new count.
    Session key might be: YYYY-MM-DD (or AM/PM split).
    """
    ref = db.collection(COL_USERS).document(user_id)
    snap = ref.get()
    data = snap.to_dict() if snap.exists else {}

    sessions = data.get("sessions", {})
    cur = int(sessions.get(session_key, 0))
    cur += 1
    sessions[session_key] = cur

    ref.set({"sessions": sessions, "updated_at": firestore.SERVER_TIMESTAMP}, merge=True)
    return cur

def get_user_trade_count(user_id: str, session_key: str) -> int:
    snap = db.collection(COL_USERS).document(user_id).get()
    if not snap.exists:
        return 0
    data = snap.to_dict() or {}
    return int((data.get("sessions", {}) or {}).get(session_key, 0))


# =========================
# ALERTING
# =========================
_twilio = None
def twilio_client():
    global _twilio
    if _twilio is not None:
        return _twilio
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TwilioClient):
        return None
    _twilio = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    return _twilio

def send_sms(body: str) -> Dict[str, Any]:
    client = twilio_client()
    if not client:
        logger.info("Twilio not configured; skipping SMS.")
        return {"ok": False, "skipped": True}

    if not (TWILIO_FROM_NUMBER and ALERT_TO_NUMBER):
        logger.info("Missing FROM/TO numbers; skipping SMS.")
        return {"ok": False, "skipped": True}

    msg = client.messages.create(
        body=body,
        from_=TWILIO_FROM_NUMBER,
        to=ALERT_TO_NUMBER
    )
    return {"ok": True, "sid": msg.sid}


# =========================
# STRATEGY PLUGINS (YOU REPLACE THESE)
# =========================
def ms_scan_market() -> List[Dict[str, Any]]:
    """
    MS: Discover candidates.
    Replace this with:
      - Your market universe source (Polygon/Alpaca/Tradier/etc.)
      - Your scanner logic (RVOL, IV, compression/expansion, etc.)
    Return list of candidates:
      {"ticker":"NVDA","bias":"LONG","ms_score":82,"reason":"..."}
    """
    # PLACEHOLDER: static demo list
    demo = [
        {"ticker": "SPY", "bias": "LONG", "ms_score": 78, "reason": "Demo candidate"},
        {"ticker": "QQQ", "bias": "SHORT", "ms_score": 74, "reason": "Demo candidate"},
    ]
    return [c for c in demo if c["ms_score"] >= MIN_MS_SCORE]

def mr_monitor_target(t: Dict[str, Any]) -> Dict[str, Any]:
    """
    MR: Monitor only targets from MS and detect if 'attack-ready'.
    Replace with your LTF/HTF alignment checks.
    Return updated fields:
      {"mr_ready": bool, "mr_score": float, "mr_note": "...", "expires_at": "..."}
    """
    # PLACEHOLDER: promote to ready if ms_score high enough
    ms_score = safe_float(t.get("ms_score"), 0)
    mr_score = ms_score  # in real life, computed separately
    mr_ready = mr_score >= (MIN_MS_SCORE + 0)  # placeholder
    return {
        "mr_ready": mr_ready,
        "mr_score": mr_score,
        "mr_note": "Demo MR monitoring",
        "expires_at": (now_ct() + timedelta(minutes=15)).isoformat(),
    }

def mcs_validate(t: Dict[str, Any]) -> Dict[str, Any]:
    """
    MCS: Validate MR-ready targets with CMP+MMP+MMG.
    Replace with your unified scoring + regime gating.
    Return:
      {"mcs_pass": bool, "mcs_score": float, "regime":"HUNT|NO_HUNT", "why":"..."}
    """
    # PLACEHOLDER: always HUNT during MS window, pass if mr_score high enough
    dt = now_ct()
    regime = "HUNT" if (is_weekday(dt) and in_window(dt, MS_START_HHMM, MS_END_HHMM)) else "NO_HUNT"
    mr_score = safe_float(t.get("mr_score"), 0)
    mcs_score = mr_score  # placeholder
    mcs_pass = (regime == "HUNT") and (mcs_score >= MIN_MCS_SCORE)
    return {"mcs_pass": mcs_pass, "mcs_score": mcs_score, "regime": regime, "why": "Demo MCS validation"}

def choose_weapon(t: Dict[str, Any]) -> Dict[str, Any]:
    """
    Weapon deployment (POE/PEE) after MS→MR→MCS approval. :contentReference[oaicite:9]{index=9}
    Replace with POE/PEE selection:
      - Options: strike, DTE, structure, delta/theta constraints
      - Equity: entry/stop logic
    """
    # PLACEHOLDER: pick POE for ETFs, PEE otherwise
    ticker = t.get("ticker", "")
    weapon = "POE" if ticker in ("SPY", "QQQ", "IWM") else "PEE"
    direction = t.get("bias", "LONG")
    return {
        "weapon": weapon,
        "direction": direction,
        "entry_zone": "DemoEntry",
        "stop": "DemoStop",
        "exit_trigger": "DemoExit",
        "confidence": int(min(99, max(1, safe_float(t.get("mcs_score"), 50)))),
    }


# =========================
# CORE ENGINE (Lifecycle)
# =========================
def session_key_for_user(dt: datetime) -> str:
    # single session per day; you can split AM/PM if desired
    return dt.strftime("%Y-%m-%d")

def can_issue_attack_now(dt: datetime) -> bool:
    # Attack window in doctrine: 8:45 AM–3:00 PM CST :contentReference[oaicite:10]{index=10}
    return is_weekday(dt) and in_window(dt, ATTACK_START_HHMM, ATTACK_END_HHMM)

def ms_step(dt: datetime) -> Dict[str, Any]:
    if not (is_weekday(dt) and in_window(dt, MS_START_HHMM, MS_END_HHMM)):
        return {"ran": False, "reason": "Outside MS window"}

    candidates = ms_scan_market()
    upserted = 0
    for c in candidates:
        ticker = c["ticker"].upper().strip()
        doc = {
            "ticker": ticker,
            "bias": c.get("bias", "LONG"),
            "ms_score": safe_float(c.get("ms_score"), 0),
            "ms_reason": c.get("reason", ""),
            "state": "DISCOVERED",
            "updated_at": firestore.SERVER_TIMESTAMP,
            "first_seen_at": firestore.SERVER_TIMESTAMP,
            "active": True,
        }
        upsert_target(ticker, doc)
        upserted += 1

    log_event("ms_step", {"count": upserted})
    return {"ran": True, "candidates": upserted}

def mr_step(dt: datetime) -> Dict[str, Any]:
    targets = list_targets()
    updated = 0
    for t in targets:
        if not t.get("active", True):
            continue
        ticker = (t.get("ticker") or t.get("_id") or "").upper()
        if not ticker:
            continue

        active_state = get_active(ticker)
        if active_state and active_state.get("status") in ("ATTACK_ISSUED", "ACTIVE"):
            # MR still monitors active positions for weakening/stand down
            # Placeholder: if expired, stand down
            expires = active_state.get("expires_at")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires)
                    if exp_dt.tzinfo is None:
                        exp_dt = TZ.localize(exp_dt)
                    if dt > exp_dt:
                        # Secondary command -> remove from active list per doctrine :contentReference[oaicite:11]{index=11}
                        remove_active(ticker)
                        upsert_target(ticker, {"state": "REMOVED", "active": False, "updated_at": firestore.SERVER_TIMESTAMP})
                        log_event("mr_secondary_remove", {"ticker": ticker})
            continue

        # Not active: normal MR monitoring
        mr = mr_monitor_target(t)
        upsert_target(ticker, {
            "state": "MONITORING",
            **mr,
            "updated_at": firestore.SERVER_TIMESTAMP,
        })
        updated += 1

    log_event("mr_step", {"updated": updated})
    return {"ran": True, "updated": updated}

def mcs_step(dt: datetime) -> Dict[str, Any]:
    targets = list_targets()
    validated = 0
    for t in targets:
        if not t.get("active", True):
            continue
        ticker = (t.get("ticker") or t.get("_id") or "").upper()
        if not ticker:
            continue

        if not t.get("mr_ready", False):
            continue

        v = mcs_validate(t)
        upsert_target(ticker, {
            "state": "VALIDATED" if v["mcs_pass"] else "REJECTED",
            **v,
            "updated_at": firestore.SERVER_TIMESTAMP,
        })
        validated += 1

    log_event("mcs_step", {"validated": validated})
    return {"ran": True, "validated": validated}

def attack_step(dt: datetime, user_id: str = "broadcast") -> Dict[str, Any]:
    """
    Issues new attacks only in attack window. :contentReference[oaicite:12]{index=12}
    Enforces user trade limit (max 3 options trades per session). :contentReference[oaicite:13]{index=13}
    """
    if not can_issue_attack_now(dt):
        return {"ran": False, "reason": "Outside attack window"}

    sess = session_key_for_user(dt)

    # In your doctrine, limit is per user trading session. :contentReference[oaicite:14]{index=14}
    # For now, user_id="broadcast" acts as a system-wide throttle placeholder.
    count = get_user_trade_count(user_id, sess)
    if count >= MAX_TRADES_PER_SESSION:
        return {"ran": False, "reason": f"Trade limit reached ({count}/{MAX_TRADES_PER_SESSION})"}

    targets = list_targets()
    issued = 0
    for t in targets:
        if issued >= (MAX_TRADES_PER_SESSION - count):
            break

        if not t.get("active", True):
            continue
        if not t.get("mcs_pass", False):
            continue

        ticker = (t.get("ticker") or t.get("_id") or "").upper()
        if not ticker:
            continue

        # If already active, skip
        if get_active(ticker):
            continue

        payload = choose_weapon(t)

        # Create active state with short expiry window (MR will remove/stand down after expiry)
        expires_at = (dt + timedelta(minutes=20)).isoformat()

        set_active(ticker, {
            "ticker": ticker,
            "status": "ATTACK_ISSUED",
            "issued_at": dt.isoformat(),
            "expires_at": expires_at,
            "weapon": payload["weapon"],
            "direction": payload["direction"],
            "entry_zone": payload["entry_zone"],
            "stop": payload["stop"],
            "exit_trigger": payload["exit_trigger"],
            "confidence": payload["confidence"],
            "regime": t.get("regime", "HUNT"),
        })

        # Update target state
        upsert_target(ticker, {
            "state": "ATTACK_ISSUED",
            "updated_at": firestore.SERVER_TIMESTAMP,
        })

        # Enforce limit counter
        new_count = increment_user_trade(user_id, sess)

        # Send alert
        sms = (
            f"MTS ATTACK | {ticker} | {payload['direction']} | {payload['weapon']} | "
            f"Entry:{payload['entry_zone']} Stop:{payload['stop']} Exit:{payload['exit_trigger']} | "
            f"Conf:{payload['confidence']} | Regime:{t.get('regime','HUNT')}"
        )
        sms_result = send_sms(sms)

        log_event("attack_issued", {"ticker": ticker, "sms": sms_result, "count": new_count})
        issued += 1

    return {"ran": True, "issued": issued}


def tick() -> Dict[str, Any]:
    """
    One tick executes the pipeline:
      MS -> MR -> MCS -> Attack
    That is exactly your finalized flow. :contentReference[oaicite:15]{index=15}
    """
    dt = now_ct()
    results = {
        "ts": dt.isoformat(),
        "ms": ms_step(dt),
        "mr": mr_step(dt),
        "mcs": mcs_step(dt),
        "attack": attack_step(dt),
    }
    return results


# =========================
# FASTAPI APP
# =========================
app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True, "service": "mts", "env": ENV}

@app.post("/tick")
async def tick_endpoint(request: Request):
    # Optional shared secret to prevent random callers
    secret = os.getenv("TICK_SECRET", "")
    if secret:
        got = request.headers.get("x-mts-secret", "")
        if got != secret:
            raise HTTPException(status_code=403, detail="Forbidden")

    out = tick()
    return JSONResponse(out)

@app.post("/pubsub/push")
async def pubsub_push(request: Request):
    """
    Optional: Pub/Sub push handler (if you choose Pub/Sub instead of Scheduler->/tick).
    """
    body = await request.json()
    # Pub/Sub push messages have {"message":{"data":"base64...","attributes":{...}}}
    log_event("pubsub_push", {"raw": body})
    out = tick()
    return JSONResponse({"ok": True, "tick": out})

@app.get("/targets")
def targets():
    return {"targets": list_targets()}

@app.get("/active")
def active():
    # list active docs (small)
    snaps = db.collection(COL_ACTIVE).limit(200).stream()
    out = []
    for s in snaps:
        d = s.to_dict()
        d["_id"] = s.id
        out.append(d)
    return {"active": out}
    
