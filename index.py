# api/index.py
# =============================================================================
#  COMPLETE BETTING APP – SINGLE FILE FOR VERCEL DEPLOYMENT
# =============================================================================

import os, uuid, hashlib, hmac, secrets, time, json
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, String, Numeric, Boolean, DateTime, ForeignKey, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# =============================================================================
#  DATABASE SETUP (SQLite – ephemeral on Vercel, replace with PostgreSQL for prod)
# =============================================================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./betting.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_uuid():
    return str(uuid.uuid4())

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, nullable=False)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    kyc_status = Column(String, default="pending")
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

class Wallet(Base):
    __tablename__ = "wallets"
    user_id = Column(String, ForeignKey("users.id"), primary_key=True)
    cash_balance = Column(Numeric(18, 2), default=0.00)
    bonus_balance = Column(Numeric(18, 2), default=0.00)
    locked_balance = Column(Numeric(18, 2), default=0.00)
    wagering_requirement = Column(Numeric(18, 2), default=0.00)
    updated_at = Column(DateTime, default=datetime.now(timezone.utc))

class Bet(Base):
    __tablename__ = "bets"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    idempotency_key = Column(String, unique=True, nullable=False)
    bet_type = Column(String, nullable=False)
    stake = Column(Numeric(18, 2), nullable=False)
    odds = Column(Numeric(10, 2), nullable=False)
    potential_payout = Column(Numeric(18, 2), nullable=False)
    actual_payout = Column(Numeric(18, 2), default=0.00)
    status = Column(String, default="open")
    selections = Column(JSON, nullable=False)
    risk_flag = Column(String, default="normal")
    settled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

class CrashRound(Base):
    __tablename__ = "crash_rounds"
    id = Column(String, primary_key=True, default=generate_uuid)
    round_number = Column(Integer, primary_key=True, autoincrement=True)
    server_seed_hash = Column(String, nullable=False)
    server_seed = Column(String, nullable=False)
    client_seed = Column(String, nullable=False)
    crash_point = Column(Numeric(10, 2), nullable=False)
    status = Column(String, default="waiting")
    started_at = Column(DateTime, nullable=True)
    crashed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

class CrashBet(Base):
    __tablename__ = "crash_bets"
    id = Column(String, primary_key=True, default=generate_uuid)
    round_id = Column(String, ForeignKey("crash_rounds.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    bet_id = Column(String, ForeignKey("bets.id"), nullable=False)
    stake = Column(Numeric(18, 2), nullable=False)
    auto_cashout_at = Column(Numeric(10, 2), nullable=True)
    cashout_multiplier = Column(Numeric(10, 2), nullable=True)
    payout = Column(Numeric(18, 2), default=0.00)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    type = Column(String, nullable=False)
    amount = Column(Numeric(18, 2), nullable=False)
    balance_before = Column(Numeric(18, 2), nullable=False)
    balance_after = Column(Numeric(18, 2), nullable=False)
    reference_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

class FraudEvent(Base):
    __tablename__ = "fraud_events"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    bet_id = Column(String, nullable=True)
    flags = Column(JSON, nullable=False)
    action = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

# =============================================================================
#  PAYOUT ENGINE
# =============================================================================
class BetType:
    SINGLE = "single"
    MULTI = "multi"
    CRASH_GAME = "crash"

class PayoutEngine:
    @staticmethod
    def calculate(stake: Decimal, odds: Decimal, bet_type: str) -> dict:
        if stake <= Decimal('0'):
            raise ValueError("Stake must be positive")
        if odds < Decimal('1.01'):
            raise ValueError("Odds must be >= 1.01")
        if bet_type not in [BetType.SINGLE, BetType.MULTI, BetType.CRASH_GAME]:
            raise ValueError("Invalid bet type")
        potential_payout = (stake * odds).quantize(Decimal('0.01'), rounding=ROUND_DOWN)
        return {
            "stake": stake,
            "odds": odds,
            "bet_type": bet_type,
            "potential_payout": potential_payout,
            "profit": potential_payout - stake
        }

    @staticmethod
    def calculate_multi_parlay(stake: Decimal, odds_list: list) -> dict:
        if not odds_list:
            raise ValueError("Multi bet requires at least one selection")
        combined = Decimal('1.00')
        for o in odds_list:
            if o < Decimal('1.01'):
                raise ValueError("Each leg must have >= 1.01")
            combined *= o
        return PayoutEngine.calculate(stake, combined, BetType.MULTI)

# =============================================================================
#  AUTH
# =============================================================================
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(401, "Invalid token")
    except JWTError:
        raise HTTPException(401, "Invalid token")
    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    db.close()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or inactive")
    return user

def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(403, "Admin access required")
    return current_user

# =============================================================================
#  SERVICES
# =============================================================================
class BetService:
    def __init__(self, db: Session):
        self.db = db

    def place_bet(self, user_id: str, stake: Decimal, bet_type: str, selections: list, idempotency_key: str) -> dict:
        # Check idempotency
        existing = self.db.query(Bet).filter(
            Bet.idempotency_key == idempotency_key,
            Bet.user_id == user_id
        ).first()
        if existing:
            return {
                "duplicate": True,
                "bet_id": existing.id,
                "status": existing.status,
                "stake": str(existing.stake),
                "potential_payout": str(existing.potential_payout),
                "profit": str(Decimal(str(existing.potential_payout)) - Decimal(str(existing.stake)))
            }

        # Combine odds
        if bet_type == BetType.SINGLE:
            combined_odds = Decimal(str(selections[0]["odds"]))
        elif bet_type == BetType.MULTI:
            odds_list = [Decimal(str(s["odds"])) for s in selections]
            combined = Decimal('1.00')
            for o in odds_list:
                combined *= o
            combined_odds = combined
        else:
            raise ValueError("Unsupported bet type")

        result = PayoutEngine.calculate(stake, combined_odds, bet_type)

        wallet = self.db.query(Wallet).filter(Wallet.user_id == user_id).first()
        if not wallet:
            raise ValueError("Wallet not found")
        available = Decimal(str(wallet.cash_balance)) - Decimal(str(wallet.locked_balance))
        if stake > available:
            raise ValueError(f"Insufficient balance. Required: {stake}, Available: {available}")

        balance_before = Decimal(str(wallet.cash_balance))
        wallet.cash_balance = balance_before - stake
        wallet.updated_at = datetime.now(timezone.utc)

        bet = Bet(
            id=generate_uuid(),
            user_id=user_id,
            idempotency_key=idempotency_key,
            bet_type=bet_type,
            stake=stake,
            odds=combined_odds,
            potential_payout=result["potential_payout"],
            status="open",
            selections=selections
        )
        self.db.add(bet)
        txn = Transaction(
            id=generate_uuid(),
            user_id=user_id,
            type="bet_placed",
            amount=-stake,
            balance_before=balance_before,
            balance_after=wallet.cash_balance,
            reference_id=bet.id
        )
        self.db.add(txn)
        self.db.commit()

        return {
            "duplicate": False,
            "bet_id": bet.id,
            "status": "accepted",
            "stake": str(stake),
            "potential_payout": str(result["potential_payout"]),
            "profit": str(result["profit"]),
            "wallet_balance": str(wallet.cash_balance)
        }

class ProvablyFair:
    @staticmethod
    def generate_server_seed() -> str:
        return secrets.token_hex(32)
    @staticmethod
    def hash_server_seed(seed: str) -> str:
        return hashlib.sha256(seed.encode()).hexdigest()
    @staticmethod
    def generate_crash_point(server_seed: str, client_seed: str, house_edge: Decimal = Decimal('0.03')) -> Decimal:
        message = client_seed.encode()
        key = server_seed.encode()
        hmac_result = hmac.new(key, message, hashlib.sha256).hexdigest()
        int_value = int(hmac_result[:8], 16)
        uniform = Decimal(int_value) / Decimal('4294967295')
        if uniform == Decimal('0'):
            uniform = Decimal('0.0000000001')
        adjusted = uniform * (Decimal('1') - house_edge)
        if adjusted >= Decimal('1'):
            crash_point = Decimal('1.00')
        else:
            crash_point = (Decimal('0.99') / (Decimal('1') - adjusted)).quantize(Decimal('0.01'))
        if crash_point < Decimal('1.01'):
            crash_point = Decimal('1.01')
        return crash_point

class CrashGameManager:
    def __init__(self):
        self.active_round: Optional[Dict] = None

    def create_round(self):
        server_seed = ProvablyFair.generate_server_seed()
        server_seed_hash = ProvablyFair.hash_server_seed(server_seed)
        client_seed = f"system_{secrets.token_hex(8)}"
        crash_point = ProvablyFair.generate_crash_point(server_seed, client_seed)

        db = SessionLocal()
        round_obj = CrashRound(
            id=generate_uuid(),
            server_seed_hash=server_seed_hash,
            server_seed=server_seed,
            client_seed=client_seed,
            crash_point=crash_point,
            status="waiting"
        )
        db.add(round_obj)
        db.commit()
        db.close()

        self.active_round = {
            "round_id": round_obj.id,
            "hash": server_seed_hash,
            "crash_point": float(crash_point),
            "status": "waiting",
            "bets": {},
            "cashed_out": set()
        }
        return self.active_round

    def place_bet(self, user_id: str, stake: Decimal, auto_cashout_at: Optional[Decimal] = None):
        if not self.active_round or self.active_round["status"] != "waiting":
            raise ValueError("No active round accepting bets")
        db = SessionLocal()
        wallet = db.query(Wallet).filter(Wallet.user_id == user_id).first()
        if not wallet:
            db.close()
            raise ValueError("Wallet not found")
        available = Decimal(str(wallet.cash_balance)) - Decimal(str(wallet.locked_balance))
        if stake > available:
            db.close()
            raise ValueError("Insufficient balance")

        wallet.cash_balance = Decimal(str(wallet.cash_balance)) - stake
        wallet.updated_at = datetime.now(timezone.utc)

        bet_id = generate_uuid()
        bet = Bet(
            id=bet_id,
            user_id=user_id,
            idempotency_key=f"crash_{self.active_round['round_id']}_{user_id}",
            bet_type="crash",
            stake=stake,
            odds=Decimal('0'),
            potential_payout=Decimal('0'),
            status="open",
            selections=[]
        )
        db.add(bet)

        crash_bet = CrashBet(
            id=generate_uuid(),
            round_id=self.active_round["round_id"],
            user_id=user_id,
            bet_id=bet_id,
            stake=stake,
            auto_cashout_at=auto_cashout_at,
            status="active"
        )
        db.add(crash_bet)

        txn = Transaction(
            id=generate_uuid(),
            user_id=user_id,
            type="bet_placed",
            amount=-stake,
            balance_before=Decimal(str(wallet.cash_balance)) + stake,
            balance_after=wallet.cash_balance,
            reference_id=bet_id
        )
        db.add(txn)
        db.commit()
        db.close()

        self.active_round["bets"][user_id] = {
            "stake": stake,
            "auto_cashout_at": float(auto_cashout_at) if auto_cashout_at else None,
            "bet_id": bet_id
        }
        return {"bet_id": bet_id, "stake": str(stake), "auto_cashout_at": str(auto_cashout_at) if auto_cashout_at else None}

    def cashout(self, user_id: str, elapsed_seconds: float):
        if not self.active_round or self.active_round["status"] != "in_progress":
            raise ValueError("Round not in progress")
        if user_id in self.active_round["cashed_out"]:
            raise ValueError("Already cashed out")
        if user_id not in self.active_round["bets"]:
            raise ValueError("No active bet")

        multiplier = Decimal(str(round(2.71828 ** (elapsed_seconds * 0.18), 2)))
        if multiplier > Decimal(str(self.active_round["crash_point"])):
            raise ValueError("Round already crashed")

        bet_data = self.active_round["bets"][user_id]
        stake = bet_data["stake"]
        result = PayoutEngine.calculate(stake, multiplier, BetType.CRASH_GAME)
        payout = result["potential_payout"]

        db = SessionLocal()
        wallet = db.query(Wallet).filter(Wallet.user_id == user_id).first()
        wallet.cash_balance = Decimal(str(wallet.cash_balance)) + payout
        wallet.updated_at = datetime.now(timezone.utc)

        bet = db.query(Bet).filter(Bet.id == bet_data["bet_id"]).first()
        bet.status = "won"
        bet.odds = multiplier
        bet.potential_payout = payout
        bet.actual_payout = payout
        bet.settled_at = datetime.now(timezone.utc)

        crash_bet = db.query(CrashBet).filter(CrashBet.bet_id == bet_data["bet_id"]).first()
        crash_bet.cashout_multiplier = multiplier
        crash_bet.payout = payout
        crash_bet.status = "cashed_out"

        txn = Transaction(
            id=generate_uuid(),
            user_id=user_id,
            type="bet_won",
            amount=payout,
            balance_before=Decimal(str(wallet.cash_balance)) - payout,
            balance_after=wallet.cash_balance,
            reference_id=bet_data["bet_id"]
        )
        db.add(txn)
        db.commit()
        db.close()

        self.active_round["cashed_out"].add(user_id)
        return {"user_id": user_id, "multiplier": str(multiplier), "payout": str(payout), "profit": str(payout - stake)}

    def crash_round(self):
        if not self.active_round:
            return
        self.active_round["status"] = "crashed"
        db = SessionLocal()
        for user_id, bet_data in self.active_round["bets"].items():
            if user_id not in self.active_round["cashed_out"]:
                bet = db.query(Bet).filter(Bet.id == bet_data["bet_id"]).first()
                if bet and bet.status == "open":
                    bet.status = "lost"
                    bet.settled_at = datetime.now(timezone.utc)
                cb = db.query(CrashBet).filter(CrashBet.bet_id == bet_data["bet_id"]).first()
                if cb:
                    cb.status = "busted"
        round_obj = db.query(CrashRound).filter(CrashRound.id == self.active_round["round_id"]).first()
        if round_obj:
            round_obj.status = "crashed"
            round_obj.crashed_at = datetime.now(timezone.utc)
        db.commit()
        db.close()

crash_manager = CrashGameManager()

# =============================================================================
#  ROUTERS
# =============================================================================
app = FastAPI(title="Betting App API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ----- Auth Router -----
auth_router = FastAPI()

class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@auth_router.post("/api/auth/register", status_code=201)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter((User.email == request.email) | (User.username == request.username)).first():
        raise HTTPException(400, "Email or username already exists")
    user = User(id=generate_uuid(), email=request.email, username=request.username,
                hashed_password=get_password_hash(request.password))
    db.add(user)
    db.flush()
    db.add(Wallet(user_id=user.id, cash_balance=0.00))
    db.commit()
    token = create_access_token({"sub": user.id})
    return {"access_token": token, "token_type": "bearer", "user_id": user.id, "username": user.username}

@auth_router.post("/api/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": user.id})
    return {"access_token": token, "token_type": "bearer", "user_id": user.id, "username": user.username}

@auth_router.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"user_id": user.id, "email": user.email, "username": user.username, "kyc_status": user.kyc_status, "is_admin": user.is_admin}

# ----- Wallet Router -----
wallet_router = FastAPI()

class DepositRequest(BaseModel):
    amount: str

@wallet_router.get("/api/wallet/balance")
def get_balance(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    w = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not w:
        raise HTTPException(404, "Wallet not found")
    avail = Decimal(str(w.cash_balance)) - Decimal(str(w.locked_balance))
    return {"cash_balance": str(w.cash_balance), "bonus_balance": str(w.bonus_balance),
            "locked_balance": str(w.locked_balance), "wagering_requirement": str(w.wagering_requirement),
            "total_available": str(avail)}

@wallet_router.post("/api/wallet/deposit")
def deposit(req: DepositRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        amt = Decimal(req.amount)
        if amt <= 0:
            raise HTTPException(400, "Amount must be positive")
    except:
        raise HTTPException(400, "Invalid amount")
    w = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not w:
        raise HTTPException(404, "Wallet not found")
    balance_before = Decimal(str(w.cash_balance))
    w.cash_balance = balance_before + amt
    txn = Transaction(id=generate_uuid(), user_id=user.id, type="deposit", amount=amt,
                      balance_before=balance_before, balance_after=w.cash_balance)
    db.add(txn)
    db.commit()
    return {"status": "success", "new_balance": str(w.cash_balance), "amount_deposited": str(amt)}

@wallet_router.get("/api/wallet/transactions")
def get_transactions(user: User = Depends(get_current_user), db: Session = Depends(get_db), limit: int = 20):
    txns = db.query(Transaction).filter(Transaction.user_id == user.id).order_by(Transaction.created_at.desc()).limit(limit).all()
    return [{"id": t.id, "type": t.type, "amount": str(t.amount), "balance_after": str(t.balance_after), "created_at": t.created_at.isoformat()} for t in txns]

# ----- Bet Router -----
bet_router = FastAPI()

class Selection(BaseModel):
    event_id: str
    market: str
    outcome: str
    odds: str

class PlaceBetRequest(BaseModel):
    stake: str
    bet_type: str
    selections: List[Selection]
    accept_odds_change: bool = False

@bet_router.post("/api/bets/place")
def place_bet(request: PlaceBetRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db),
              x_idempotency_key: str = Header(None, alias="X-Idempotency-Key")):
    if not x_idempotency_key:
        raise HTTPException(400, "X-Idempotency-Key required")
    try:
        stake = Decimal(request.stake)
    except:
        raise HTTPException(400, "Invalid stake")
    selections = [s.model_dump() for s in request.selections]
    service = BetService(db)
    try:
        res = service.place_bet(user.id, stake, request.bet_type, selections, x_idempotency_key)
        return res
    except ValueError as e:
        raise HTTPException(422, str(e))

@bet_router.get("/api/bets/history")
def bet_history(user: User = Depends(get_current_user), db: Session = Depends(get_db),
                limit: int = 20, status: Optional[str] = None):
    q = db.query(Bet).filter(Bet.user_id == user.id)
    if status:
        q = q.filter(Bet.status == status)
    bets = q.order_by(Bet.created_at.desc()).limit(limit).all()
    return [{"bet_id": b.id, "bet_type": b.bet_type, "stake": str(b.stake), "odds": str(b.odds),
             "potential_payout": str(b.potential_payout), "actual_payout": str(b.actual_payout),
             "status": b.status, "selections": b.selections, "created_at": b.created_at.isoformat()} for b in bets]

# ----- Crash Router -----
crash_router = FastAPI()
class CrashBetRequest(BaseModel):
    stake: str
    auto_cashout_at: Optional[str] = None
class CashoutRequest(BaseModel):
    elapsed_seconds: float

@crash_router.get("/api/crash/current-round")
def current_round():
    if not crash_manager.active_round:
        crash_manager.create_round()
    r = crash_manager.active_round
    return {"round_id": r["round_id"], "hash": r["hash"], "status": r["status"], "player_count": len(r["bets"]),
            "crash_point": r["crash_point"] if r["status"] == "crashed" else None}

@crash_router.post("/api/crash/new-round")
def new_round():
    crash_manager.create_round()
    return {"status": "waiting", "round_id": crash_manager.active_round["round_id"], "hash": crash_manager.active_round["hash"]}

@crash_router.post("/api/crash/place-bet")
def place_crash_bet(req: CrashBetRequest, user: User = Depends(get_current_user)):
    try:
        stake = Decimal(req.stake)
        auto = Decimal(req.auto_cashout_at) if req.auto_cashout_at else None
        res = crash_manager.place_bet(user.id, stake, auto)
        return {"status": "accepted", **res}
    except ValueError as e:
        raise HTTPException(422, str(e))

@crash_router.post("/api/crash/cashout")
def cashout_crash(req: CashoutRequest, user: User = Depends(get_current_user)):
    try:
        res = crash_manager.cashout(user.id, req.elapsed_seconds)
        return {"status": "cashed_out", **res}
    except ValueError as e:
        raise HTTPException(422, str(e))

@crash_router.post("/api/crash/start-round")
def start_round():
    if not crash_manager.active_round:
        raise HTTPException(400, "No active round")
    crash_manager.active_round["status"] = "in_progress"
    crash_manager.active_round["start_time"] = time.time()
    return {"status": "started"}

@crash_router.post("/api/crash/crash-round")
def crash_round_endpoint():
    crash_manager.crash_round()
    return {"status": "crashed", "crash_point": str(crash_manager.active_round["crash_point"])}

# ----- Admin Router -----
admin_router = FastAPI()

@admin_router.get("/api/admin/dashboard/summary")
def admin_dashboard(admin: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    bets_today = db.query(Bet).filter(Bet.created_at >= today).all()
    total_stakes = sum(Decimal(str(b.stake)) for b in bets_today)
    total_payouts = sum(Decimal(str(b.actual_payout)) for b in bets_today if b.status in ("won", "void"))
    pnl = total_stakes - total_payouts
    active = crash_manager.active_round
    return {"pnl": {"today": f"+{pnl}" if pnl >= 0 else str(pnl), "total_stakes": str(total_stakes), "total_payouts": str(total_payouts)},
            "users": {"total": db.query(User).count(), "online_now": db.query(User).filter(User.is_active == True).count()},
            "bets": {"open": db.query(Bet).filter(Bet.status == "open").count(), "total_today": len(bets_today)},
            "crash_game": {"active_round": active["round_id"] if active else None, "status": active["status"] if active else "no_round",
                           "players": len(active["bets"]) if active else 0},
            "system_health": "operational"}

@admin_router.get("/api/admin/recent-bets")
def recent_bets(admin: User = Depends(get_admin_user), db: Session = Depends(get_db), limit: int = 50):
    bets = db.query(Bet).order_by(Bet.created_at.desc()).limit(limit).all()
    return [{"bet_id": b.id, "user_id": b.user_id, "type": b.bet_type, "stake": str(b.stake), "odds": str(b.odds),
             "payout": str(b.actual_payout), "status": b.status, "created_at": b.created_at.isoformat()} for b in bets]

# =============================================================================
#  MOUNT ALL ROUTERS & ADMIN HTML
# =============================================================================
app.mount("/api/auth", auth_router)
app.mount("/api/wallet", wallet_router)
app.mount("/api/bets", bet_router)
app.mount("/api/crash", crash_router)
app.mount("/api/admin", admin_router)

@app.on_event("startup")
def startup():
    # Create admin user if not exists
    db = SessionLocal()
    admin = db.query(User).filter(User.email == "admin@bettingapp.com").first()
    if not admin:
        admin = User(id=generate_uuid(), email="admin@bettingapp.com", username="admin",
                     hashed_password=get_password_hash("admin123"), is_admin=True, kyc_status="approved")
        db.add(admin)
        db.commit()
        db.add(Wallet(user_id=admin.id, cash_balance=1000000.00))
        db.commit()
    db.close()
    crash_manager.create_round()

@app.get("/admin")
def admin_panel():
    # Serves the admin dashboard HTML
    return """
    <!DOCTYPE html><html><head><title>Betting Admin</title>
    <style>body{font-family:sans-serif;background:#0a0a0a;color:#fff;padding:20px}
    .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px}
    .card{background:#1a1a1a;border-radius:10px;padding:20px;border:1px solid #333}
    .card h3{color:#888;font-size:12px;text-transform:uppercase;margin-bottom:8px}
    .card .value{font-size:28px;font-weight:bold}
    .positive{color:#00ff88}.negative{color:#ff4444}
    table{width:100%;border-collapse:collapse;background:#1a1a1a;border-radius:10px}
    th{background:#222;padding:12px;text-align:left;font-size:12px;color:#888}
    td{padding:12px;border-bottom:1px solid #222}
    .status-open{color:#ffaa00}.status-won{color:#00ff88}.status-lost{color:#ff4444}
    .btn{background:#00ff88;color:#000;border:none;padding:8px 16px;border-radius:5px;cursor:pointer}
    </style></head><body>
    <h1>Betting Admin Dashboard</h1>
    <div id="cards" class="cards"></div>
    <h2>Recent Bets</h2>
    <table><thead><tr><th>Bet</th><th>User</th><th>Type</th><th>Stake</th><th>Odds</th><th>Payout</th><th>Status</th><th>Time</th></tr></thead><tbody id="bets"></tbody></table>
    <p id="updated"></p>
    <script>
    const API='/api/admin'; let TOKEN=localStorage.getItem('at');
    async function f(url){const r=await fetch(url,{headers:{Authorization:'Bearer '+TOKEN}});if(r.status==401){TOKEN=prompt('Admin token? Login at /api/auth/login as admin@bettingapp.com / admin123');localStorage.setItem('at',TOKEN);return f(url);}return r.json();}
    async function refresh(){const s=await f(API+'/dashboard/summary');const b=await f(API+'/recent-bets');
    document.getElementById('cards').innerHTML=`<div class="card"><h3>P&L Today</h3><div class="value ${s.pnl.today.startsWith('+')?'positive':'negative'}">${s.pnl.today}</div></div><div class="card"><h3>Total Stakes</h3><div class="value">$${s.pnl.total_stakes}</div></div><div class="card"><h3>Open Bets</h3><div class="value">${s.bets.open}</div></div><div class="card"><h3>Crash</h3><div class="value">${s.crash_game.status}</div></div>`;
    document.getElementById('bets').innerHTML=b.map(x=>`<tr><td>${x.bet_id.slice(0,8)}</td><td>${x.user_id.slice(0,8)}</td><td>${x.type}</td><td>$${x.stake}</td><td>${x.odds}x</td><td>$${x.payout}</td><td class="status-${x.status}">${x.status}</td><td>${new Date(x.created_at).toLocaleTimeString()}</td></tr>`).join('');
    document.getElementById('updated').textContent='Updated: '+new Date().toLocaleTimeString();}
    if(!TOKEN){TOKEN=prompt('Admin token? Login as admin@bettingapp.com / admin123');localStorage.setItem('at',TOKEN);}
    refresh();setInterval(refresh,10000);</script></body></html>
    """

@app.get("/")
def root():
    return {"app": "Betting Platform API", "version": "1.0.0", "docs": "/docs", "admin": "/admin"}
