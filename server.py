from dotenv import load_dotenv
load_dotenv()

import os
import logging
import secrets
import string
import hmac
import hashlib
import httpx
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Literal, Dict, Any

import bcrypt
import jwt
from bson import ObjectId
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field

ROOT_DIR = Path(__file__).parent
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]
app = FastAPI(title="DataEarn API")
api_router = APIRouter(prefix="/api")
JWT_ALGORITHM = "HS256"

RATE_PER_MB = 0.45                # Base rate: 1 MB = ₹0.45
BOOST_MULTIPLIER = 3              # Telegram-verified members earn 3× base rate
BOOSTED_RATE_PER_MB = RATE_PER_MB * BOOST_MULTIPLIER   # 1 MB = ₹1.35 (3× boost)
REFERRAL_REWARD = 50.0            # ₹50 per verified referral
MIN_WITHDRAWAL = 500.0
DEPOSIT_REQUIRED = 100.0

# Telegram Login Widget + Bot API for real membership check
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "@DataEarnOfficial")
TELEGRAM_CHANNEL_URL = os.environ.get("TELEGRAM_CHANNEL_URL", "https://t.me/DataEarnOfficial")
TELEGRAM_AUTH_MAX_AGE = 86400     # widget auth valid for 24h


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def token(user_id: str, email: str, kind: str, days: int):
    return jwt.encode(
        {"sub": user_id, "email": email, "type": kind,
         "exp": datetime.now(timezone.utc) + timedelta(days=days)},
        os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM
    )


def gen_ref_code(name: str) -> str:
    prefix = "".join(c for c in (name or "USER").upper() if c.isalpha())[:4] or "USER"
    suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    return f"{prefix}{suffix}"


def public_user(doc: dict):
    return {
        "id": str(doc.get("_id", "")),
        "name": doc.get("name", ""),
        "email": doc["email"],
        "role": doc.get("role", "user"),
        "points": doc.get("points", 0),
        "consent": doc.get("consent", False),
        "wallet_balance": round(doc.get("wallet_balance", 0.0), 2),
        "total_data_sold": round(doc.get("total_data_sold", 0.0), 2),
        "total_earnings": round(doc.get("total_earnings", 0.0), 2),
        "referral_code": doc.get("referral_code", ""),
        "referral_earnings": round(doc.get("referral_earnings", 0.0), 2),
        "telegram_verified": bool(doc.get("telegram_verified", False)),
        "telegram_started_at": doc.get("telegram_started_at"),
        "rate_per_mb": BOOSTED_RATE_PER_MB if doc.get("telegram_verified") else RATE_PER_MB,
        "created_at": doc.get("created_at", now_iso()),
    }


class RegisterInput(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8)
    referral_code: Optional[str] = None
    consent: bool = False


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class ConsentInput(BaseModel):
    consent: bool


class SessionEndInput(BaseModel):
    data_mb: float = Field(ge=0)


class WithdrawInput(BaseModel):
    amount: float = Field(ge=MIN_WITHDRAWAL)
    method: Literal["upi", "bank"]
    upi_id: Optional[str] = None
    bank_name: Optional[str] = None
    bank_acc: Optional[str] = None
    bank_ifsc: Optional[str] = None


class WithdrawStatusInput(BaseModel):
    status: Literal["Pending", "Processing", "Completed", "Rejected"]
    admin_note: Optional[str] = None


async def current_user(request: Request):
    raw = request.cookies.get("access_token")
    if not raw:
        auth = request.headers.get("Authorization", "")
        raw = auth[7:] if auth.startswith("Bearer ") else None
    if not raw:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(raw, os.environ["JWT_SECRET"], algorithms=[JWT_ALGORITHM])
        doc = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not doc:
            raise HTTPException(401, "User not found")
        return doc
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired session")


async def ensure_referral_code(user_doc):
    if not user_doc.get("referral_code"):
        for _ in range(6):
            code = gen_ref_code(user_doc.get("name", ""))
            if not await db.users.find_one({"referral_code": code}):
                await db.users.update_one({"_id": user_doc["_id"]}, {"$set": {"referral_code": code}})
                user_doc["referral_code"] = code
                return code
    return user_doc.get("referral_code")


async def seed_leaderboard_demo():
    """Seed demo Indian participants so the leaderboard feels alive on a fresh install.
    Idempotent: each demo user is inserted only if their email isn't already present.
    """
    demo_participants = [
        ("Aarav Sharma",   4218.75, 3125.0, True),
        ("Priya Iyer",     3892.15, 2883.0, True),
        ("Rohan Verma",    3204.90, 2374.0, True),
        ("Ananya Reddy",   2876.45, 6392.0, False),
        ("Vihaan Patel",   2415.30, 5367.0, False),
        ("Diya Kapoor",    2168.75, 1606.0, True),
        ("Kabir Nair",     1927.80, 4284.0, False),
        ("Saanvi Desai",   1683.15, 1247.0, True),
        ("Arjun Singh",    1452.60, 3228.0, False),
        ("Myra Agarwal",   1237.20, 916.0,  True),
        ("Ishaan Menon",   1043.55, 2319.0, False),
        ("Kavya Malhotra",  876.40,  649.0, True),
        ("Reyansh Gupta",   712.80, 1584.0, False),
        ("Aisha Khan",      589.35,  436.0, True),
        ("Aditya Rao",      423.60,  941.0, False),
        ("Zara Choudhary",  312.75,  231.0, True),
        ("Vivaan Bansal",   204.30,  453.0, False),
        ("Aadhya Joshi",    137.55,  101.0, True),
    ]

    docs = []
    for name, earnings, data_sold, verified in demo_participants:
        email = f"{name.lower().replace(' ', '.')}@dataearn.demo"
        if await db.users.find_one({"email": email}):
            continue
        docs.append({
            "name": name,
            "email": email,
            "password_hash": hash_password(secrets.token_urlsafe(24)),  # unusable
            "role": "user",
            "points": 0,
            "consent": True,
            "wallet_balance": round(earnings * 0.55, 2),
            "total_data_sold": data_sold,
            "total_earnings": earnings,
            "referral_code": gen_ref_code(name),
            "referral_earnings": round(earnings * 0.12, 2),
            "telegram_verified": verified,
            "telegram_verified_at": now_iso() if verified else None,
            "created_at": now_iso(),
            "is_demo": True,
        })
    if docs:
        try:
            await db.users.insert_many(docs, ordered=False)
        except Exception:
            pass


async def seed_admin():
    email = os.environ["ADMIN_EMAIL"].lower()
    existing = await db.users.find_one({"email": email})
    if not existing:
        await db.users.insert_one({
            "name": "DataEarn Admin", "email": email,
            "password_hash": hash_password(os.environ["ADMIN_PASSWORD"]),
            "role": "admin", "points": 0, "consent": True,
            "wallet_balance": 0.0, "total_data_sold": 0.0, "total_earnings": 0.0,
            "referral_code": "ADMIN001", "referral_earnings": 0.0,
            "created_at": now_iso()
        })
    elif not verify_password(os.environ["ADMIN_PASSWORD"], existing["password_hash"]):
        await db.users.update_one({"_id": existing["_id"]},
                                  {"$set": {"password_hash": hash_password(os.environ["ADMIN_PASSWORD"])}})
    await db.users.create_index("email", unique=True)
    await db.users.create_index("referral_code", unique=True, sparse=True)
    await db.users.create_index("telegram_user_id", unique=True, sparse=True)


@app.on_event("startup")
async def startup():
    await seed_admin()
    await seed_leaderboard_demo()


@api_router.get("/")
async def root():
    return {"message": "DataEarn API is ready"}


# ---------------- AUTH ----------------

@api_router.post("/auth/register")
async def register(payload: RegisterInput, response: Response):
    email = payload.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    inviter = None
    if payload.referral_code:
        inviter = await db.users.find_one({"referral_code": payload.referral_code.upper()})

    # Generate unique referral code
    code = None
    for _ in range(6):
        candidate = gen_ref_code(payload.name)
        if not await db.users.find_one({"referral_code": candidate}):
            code = candidate
            break
    if not code:
        code = secrets.token_hex(4).upper()

    doc = {
        "name": payload.name, "email": email,
        "password_hash": hash_password(payload.password),
        "role": "user", "points": 0, "consent": payload.consent,
        "wallet_balance": 0.0, "total_data_sold": 0.0, "total_earnings": 0.0,
        "referral_code": code, "referral_earnings": 0.0,
        "referred_by": inviter["referral_code"] if inviter else None,
        "created_at": now_iso()
    }
    result = await db.users.insert_one(doc)

    # Credit inviter with ₹50
    if inviter:
        await db.users.update_one(
            {"_id": inviter["_id"]},
            {"$inc": {"wallet_balance": REFERRAL_REWARD,
                      "total_earnings": REFERRAL_REWARD,
                      "referral_earnings": REFERRAL_REWARD}}
        )
        await db.referrals.insert_one({
            "inviter_id": str(inviter["_id"]),
            "inviter_code": inviter["referral_code"],
            "invitee_id": str(result.inserted_id),
            "invitee_name": payload.name,
            "invitee_email": email,
            "amount": REFERRAL_REWARD,
            "created_at": now_iso()
        })

    user = public_user({**doc, "_id": result.inserted_id})
    response.set_cookie("access_token", token(str(result.inserted_id), email, "access", 1),
                        httponly=True, samesite="none", secure=True, max_age=900)
    response.set_cookie("refresh_token", token(str(result.inserted_id), email, "refresh", 7),
                        httponly=True, samesite="none", secure=True, max_age=604800)
    return user


@api_router.post("/auth/login")
async def login(payload: LoginInput, response: Response):
    doc = await db.users.find_one({"email": payload.email.lower()})
    if not doc or not verify_password(payload.password, doc["password_hash"]):
        raise HTTPException(401, "Email or password is incorrect")
    await ensure_referral_code(doc)
    response.set_cookie("access_token", token(str(doc["_id"]), doc["email"], "access", 1),
                        httponly=True, samesite="none", secure=True, max_age=900)
    response.set_cookie("refresh_token", token(str(doc["_id"]), doc["email"], "refresh", 7),
                        httponly=True, samesite="none", secure=True, max_age=604800)
    return public_user(doc)


@api_router.get("/auth/me")
async def me(user=Depends(current_user)):
    return public_user(user)


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"ok": True}


@api_router.post("/user/consent")
async def consent(payload: ConsentInput, user=Depends(current_user)):
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"consent": payload.consent}})
    return {"consent": payload.consent}


# ---------------- WALLET / SESSION ----------------

@api_router.get("/wallet")
async def wallet(user=Depends(current_user)):
    await ensure_referral_code(user)
    fresh = await db.users.find_one({"_id": user["_id"]})
    return public_user(fresh)


@api_router.post("/session/end")
async def session_end(payload: SessionEndInput, user=Depends(current_user)):
    if payload.data_mb <= 0:
        raise HTTPException(400, "No data recorded for this session")
    # Rate is determined server-side by verified Telegram status only
    telegram_verified = bool(user.get("telegram_verified", False))
    rate = BOOSTED_RATE_PER_MB if telegram_verified else RATE_PER_MB
    earnings = round(payload.data_mb * rate, 2)
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$inc": {
            "wallet_balance": earnings,
            "total_data_sold": payload.data_mb,
            "total_earnings": earnings
        }}
    )
    await db.sessions.insert_one({
        "user_id": str(user["_id"]),
        "user_name": user.get("name", ""),
        "data_mb": round(payload.data_mb, 2),
        "earnings": earnings,
        "rate": rate,
        "boosted": telegram_verified,
        "created_at": now_iso()
    })
    fresh = await db.users.find_one({"_id": user["_id"]})
    return {"earnings": earnings, "data_mb": payload.data_mb, "boosted": telegram_verified, "wallet": public_user(fresh)}


# ---------------- WITHDRAWALS ----------------

def strip_withdrawal(w: dict):
    return {
        "withdrawal_id": w.get("withdrawal_id"),
        "user_id": w.get("user_id"),
        "user_name": w.get("user_name"),
        "amount": w.get("amount"),
        "method": w.get("method"),
        "destination": w.get("destination"),
        "status": w.get("status"),
        "created_at": w.get("created_at"),
        "updated_at": w.get("updated_at"),
        "admin_note": w.get("admin_note"),
    }


@api_router.post("/withdrawal/request")
async def withdrawal_request(payload: WithdrawInput, user=Depends(current_user)):
    if payload.amount < MIN_WITHDRAWAL:
        raise HTTPException(400, f"Minimum withdrawal is ₹{int(MIN_WITHDRAWAL)}")
    wallet = user.get("wallet_balance", 0.0)
    if payload.amount > wallet:
        raise HTTPException(400, "Amount exceeds wallet balance")
    if payload.method == "upi" and not (payload.upi_id or "").strip():
        raise HTTPException(400, "UPI ID is required")
    if payload.method == "bank" and not (payload.bank_name and payload.bank_acc and payload.bank_ifsc):
        raise HTTPException(400, "Complete bank details are required")

    destination = payload.upi_id if payload.method == "upi" else (
        f"{payload.bank_name} · A/C {payload.bank_acc[-4:].rjust(len(payload.bank_acc), '*')} · {payload.bank_ifsc}"
    )
    record = {
        "withdrawal_id": "WD-" + secrets.token_hex(4).upper(),
        "user_id": str(user["_id"]),
        "user_name": user.get("name", ""),
        "amount": round(payload.amount, 2),
        "method": "UPI" if payload.method == "upi" else "Bank Transfer",
        "destination": destination,
        "status": "Pending",
        "deposit_required": DEPOSIT_REQUIRED,
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.withdrawals.insert_one(record)
    # Hold the amount from wallet (debits on request; refunded on rejection)
    await db.users.update_one({"_id": user["_id"]},
                              {"$inc": {"wallet_balance": -round(payload.amount, 2)}})
    fresh = await db.users.find_one({"_id": user["_id"]})
    return {"withdrawal": strip_withdrawal(record), "wallet": public_user(fresh)}


@api_router.get("/withdrawal/list")
async def withdrawal_list(user=Depends(current_user)):
    items = await db.withdrawals.find({"user_id": str(user["_id"])}).sort("created_at", -1).to_list(50)
    return [strip_withdrawal(w) for w in items]


# ---------------- REFERRALS ----------------

@api_router.get("/referrals")
async def referrals(user=Depends(current_user)):
    code = await ensure_referral_code(user)
    items = await db.referrals.find({"inviter_id": str(user["_id"])}).sort("created_at", -1).to_list(100)
    total = sum(r.get("amount", 0) for r in items)
    return {
        "referral_code": code,
        "count": len(items),
        "earnings": round(total, 2),
        "reward_per_referral": REFERRAL_REWARD,
        "list": [{"name": r.get("invitee_name"), "date": r.get("created_at", "")[:10], "amount": r.get("amount", 0)} for r in items]
    }


# ---------------- TELEGRAM VERIFICATION (Login Widget + Bot API) ----------------

class TelegramLoginInput(BaseModel):
    id: int
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    username: Optional[str] = ""
    photo_url: Optional[str] = ""
    auth_date: int
    hash: str


def verify_telegram_widget_hash(payload: Dict[str, Any], bot_token: str) -> bool:
    """Verify Telegram Login Widget hash per official docs:
    - build data_check_string = sorted "key=value" joined by newlines, excluding 'hash'
    - secret_key = SHA256(bot_token) (raw bytes)
    - expected = HMAC_SHA256(data_check_string, secret_key).hexdigest()
    - compare in constant time to payload['hash']
    """
    provided_hash = payload.get("hash", "")
    check_dict = {k: v for k, v in payload.items() if k != "hash" and v not in (None, "")}
    data_check = "\n".join(f"{k}={check_dict[k]}" for k in sorted(check_dict.keys()))
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    expected = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_hash)


async def telegram_is_member(user_id: int) -> bool:
    """Call bot getChatMember on our channel. Returns True for member/admin/creator."""
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(500, "Telegram bot is not configured")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChatMember"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(url, params={"chat_id": TELEGRAM_CHAT_ID, "user_id": user_id})
    data = r.json()
    if not data.get("ok"):
        desc = data.get("description", "Telegram API error")
        # Common: "user not found" or "PARTICIPANT_ID_INVALID" → user isn't in the chat
        if "not found" in desc.lower() or "participant" in desc.lower():
            return False
        raise HTTPException(502, f"Telegram check failed: {desc}")
    status = (data.get("result") or {}).get("status")
    return status in ("creator", "administrator", "member", "restricted")


@api_router.get("/telegram/config")
async def telegram_config():
    """Return bot username + channel URL so the frontend can render the Login Widget."""
    return {
        "bot_username": TELEGRAM_BOT_USERNAME,
        "channel_url": TELEGRAM_CHANNEL_URL,
        "channel_id": TELEGRAM_CHAT_ID,
        "boost_multiplier": BOOST_MULTIPLIER,
        "base_rate": RATE_PER_MB,
        "boosted_rate": BOOSTED_RATE_PER_MB,
    }


@api_router.post("/telegram/verify-login")
async def telegram_verify_login(payload: TelegramLoginInput, user=Depends(current_user)):
    """Verify Telegram Login Widget payload, then check channel membership via Bot API."""
    if user.get("telegram_verified"):
        return {"telegram_verified": True, "already": True}

    # 1. Verify widget hash
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(500, "Telegram bot is not configured")
    data = payload.model_dump()
    if not verify_telegram_widget_hash(data, TELEGRAM_BOT_TOKEN):
        raise HTTPException(401, "Telegram login signature is invalid")

    # 2. Check auth_date freshness
    age = datetime.now(timezone.utc).timestamp() - payload.auth_date
    if age < 0 or age > TELEGRAM_AUTH_MAX_AGE:
        raise HTTPException(401, "Telegram login has expired — please try again")

    # 3. Prevent duplicate claims across accounts — this Telegram user must not be linked elsewhere
    existing = await db.users.find_one({"telegram_user_id": payload.id})
    if existing and str(existing.get("_id")) != str(user["_id"]):
        raise HTTPException(409, "This Telegram account has already been used to claim the bonus")

    # 4. Verify channel membership via Bot API
    is_member = await telegram_is_member(payload.id)
    if not is_member:
        raise HTTPException(
            403,
            f"You are not a member of {TELEGRAM_CHAT_ID}. Please join the channel and try again.",
        )

    # 5. Mark verified — persist Telegram identity to prevent duplicate claims
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "telegram_verified": True,
            "telegram_verified_at": now_iso(),
            "telegram_user_id": payload.id,
            "telegram_username": payload.username or "",
            "telegram_first_name": payload.first_name or "",
        }}
    )
    return {
        "telegram_verified": True,
        "boost_multiplier": BOOST_MULTIPLIER,
        "new_rate_per_mb": BOOSTED_RATE_PER_MB,
        "telegram_username": payload.username or "",
    }


# ---------------- LEADERBOARD ----------------

@api_router.get("/leaderboard")
async def leaderboard(user=Depends(current_user)):
    docs = await db.users.find(
        {"role": "user"},
        {"name": 1, "total_earnings": 1, "total_data_sold": 1, "telegram_verified": 1}
    ).sort("total_earnings", -1).limit(10).to_list(10)

    def mask_name(n):
        if not n:
            return "Anonymous"
        parts = n.strip().split()
        first = parts[0]
        if len(parts) > 1:
            return f"{first} {parts[-1][0].upper()}."
        return first

    entries = []
    for i, d in enumerate(docs):
        entries.append({
            "rank": i + 1,
            "name": mask_name(d.get("name", "")),
            "total_earnings": round(d.get("total_earnings", 0.0), 2),
            "total_data_sold": round(d.get("total_data_sold", 0.0), 2),
            "telegram_verified": bool(d.get("telegram_verified", False)),
            "is_you": str(d.get("_id")) == str(user["_id"]),
        })

    # Include self position if not in top 10
    self_rank = None
    if not any(e["is_you"] for e in entries):
        higher = await db.users.count_documents({
            "role": "user",
            "total_earnings": {"$gt": user.get("total_earnings", 0.0)}
        })
        self_rank = {
            "rank": higher + 1,
            "name": mask_name(user.get("name", "")),
            "total_earnings": round(user.get("total_earnings", 0.0), 2),
            "total_data_sold": round(user.get("total_data_sold", 0.0), 2),
            "telegram_verified": bool(user.get("telegram_verified", False)),
            "is_you": True,
        }

    return {"top": entries, "you": self_rank}


# ---------------- ADMIN ----------------

def require_admin(user):
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")


@api_router.get("/admin/overview")
async def admin_overview(user=Depends(current_user)):
    require_admin(user)
    users_count = await db.users.count_documents({"role": "user"})
    with_consent = await db.users.count_documents({"role": "user", "consent": True})
    withdrawals = await db.withdrawals.find({}).sort("created_at", -1).to_list(200)
    pending = len([w for w in withdrawals if w.get("status") == "Pending"])
    total_paid = sum(w.get("amount", 0) for w in withdrawals if w.get("status") == "Completed")

    user_docs = await db.users.find({"role": "user"}).sort("created_at", -1).to_list(50)
    return {
        "metrics": {
            "users": users_count,
            "active": with_consent,
            "pending": pending,
            "rewards": f"₹{total_paid:.0f}",
        },
        "users": [{
            "id": str(u["_id"]),
            "name": u.get("name", ""),
            "email": u.get("email", ""),
            "points": int(u.get("wallet_balance", 0)),
            "status": "Active" if u.get("consent") else "Inactive",
            "joined": (u.get("created_at") or "")[:10],
        } for u in user_docs],
        "withdrawals": [strip_withdrawal(w) for w in withdrawals[:50]],
    }


@api_router.get("/admin/withdrawals")
async def admin_withdrawals(user=Depends(current_user)):
    require_admin(user)
    items = await db.withdrawals.find({}).sort("created_at", -1).to_list(200)
    return [strip_withdrawal(w) for w in items]


@api_router.post("/admin/withdrawals/{wid}/status")
async def admin_withdrawal_status(wid: str, payload: WithdrawStatusInput, user=Depends(current_user)):
    require_admin(user)
    w = await db.withdrawals.find_one({"withdrawal_id": wid})
    if not w:
        raise HTTPException(404, "Withdrawal not found")

    prev = w.get("status")
    updates = {"status": payload.status, "updated_at": now_iso()}
    if payload.admin_note is not None:
        updates["admin_note"] = payload.admin_note

    # If rejecting a previously-non-rejected withdrawal, refund to user's wallet
    if payload.status == "Rejected" and prev != "Rejected":
        await db.users.update_one(
            {"_id": ObjectId(w["user_id"])},
            {"$inc": {"wallet_balance": w.get("amount", 0)}}
        )
    # If moving away from Rejected back to active, re-hold funds if possible
    if prev == "Rejected" and payload.status != "Rejected":
        target = await db.users.find_one({"_id": ObjectId(w["user_id"])})
        if target and target.get("wallet_balance", 0) >= w.get("amount", 0):
            await db.users.update_one(
                {"_id": ObjectId(w["user_id"])},
                {"$inc": {"wallet_balance": -w.get("amount", 0)}}
            )
        else:
            raise HTTPException(400, "User has insufficient balance to re-hold this amount")

    await db.withdrawals.update_one({"withdrawal_id": wid}, {"$set": updates})
    fresh = await db.withdrawals.find_one({"withdrawal_id": wid})
    return strip_withdrawal(fresh)


app.include_router(api_router)
app.add_middleware(
    CORSMiddleware, allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"], allow_headers=["*"],
)
logging.basicConfig(level=logging.INFO)


@app.on_event("shutdown")
async def shutdown():
    client.close()
