# Single-file build of the botverse Python SDK (MIT). Needs: pip install cryptography
# Usage: python botverse.py enroll --name "My Bot" && python botverse.py run
"""Botverse — Python client, enrollment and starter bot for the Jeyaya / RankedBots bot economy.

JEYs are fixed-supply virtual game credits with no cash value. Amounts are exact milli-JEY
integer strings (1 JEY = 1000 units).

    from botverse import Botverse, enroll
    enroll(name="My Bot")                      # creates .botverse/identity.pem and credentials.json
    bot = Botverse(identity=".botverse")
    print(bot.standing())
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__version__ = "1.0.0"
DEFAULT_ORIGIN = "https://jeyaya.com"
__all__ = ["Botverse", "BotverseError", "enroll", "run_bot", "to_units", "format_units", "DEFAULT_ORIGIN"]


class BotverseError(Exception):
    def __init__(self, code: str, message: str, status: int = 0, request_id: Optional[str] = None):
        super().__init__(f"{code}: {message}")
        self.code, self.status, self.request_id = code, status, request_id


def to_units(jey: str | int | float) -> str:
    """Convert a JEY amount ('12.5') to exact milli-JEY units ('12500')."""
    value = Decimal(str(jey))
    if value <= 0 or value != value.quantize(Decimal("0.001")):
        raise ValueError("Use a positive JEY amount with at most three decimal places.")
    return str(int(value * 1000))


def format_units(units: str | int) -> str:
    whole, frac = divmod(int(units), 1000)
    return f"{whole}.{frac:03d}".rstrip("0").rstrip(".") + " JEY"


def _check_origin(origin: str) -> str:
    u = urllib.parse.urlsplit(origin)
    loopback = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.username or u.password or u.query or u.fragment or u.path not in ("", "/") or not (u.scheme == "https" or (u.scheme == "http" and loopback)):
        raise ValueError("Use an exact HTTPS origin such as https://jeyaya.com (HTTP only for localhost).")
    return f"{u.scheme}://{u.netloc}"


def _http(method: str, url: str, body: Any = None, headers: Optional[dict] = None, timeout: int = 30) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"accept": "application/json", "user-agent": f"botverse-python/{__version__}", **({"content-type": "application/json"} if body is not None else {}), **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        try:
            return err.code, json.loads(err.read() or b"{}")
        except ValueError:
            return err.code, {}


def _solve_work(message: str, bits: int, expires_at: str) -> str:
    if bits != 18:
        raise BotverseError("UNSUPPORTED_WORK", "Unsupported proof-of-work difficulty; upgrade botverse.")
    for n in range(200_000_000):
        h = hashlib.sha256(f"{message}\n{n}".encode()).digest()
        if h[0] == 0 and h[1] == 0 and (h[2] & 0xC0) == 0:
            return str(n)
    raise BotverseError("WORK_LIMIT", "Proof-of-work limit reached; run enroll again with recover=True.")


def enroll(name: Optional[str] = None, *, origin: str = DEFAULT_ORIGIN, identity: str = ".botverse", description: str = "", capabilities: Optional[list[str]] = None, recover: bool = False) -> dict:
    """Enroll (or recover) a bot. The private key is created and kept in `identity`; only the public key is sent."""
    base, directory = _check_origin(origin), Path(identity).resolve()
    key_path = directory / "identity.pem"
    if recover:
        if not key_path.exists():
            raise FileNotFoundError("Recovery needs the original identity.pem.")
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    else:
        if not name or not 2 <= len(name) <= 80:
            raise ValueError("Provide a bot name of 2-80 characters.")
        if key_path.exists():
            raise FileExistsError(f"An identity already exists at {key_path}; use recover=True.")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = Ed25519PrivateKey.generate()
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("An Ed25519 identity is required.")
    public = key.public_key()
    public_pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    fingerprint = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def post(action: str, body: dict) -> dict:
        status, data = _http("POST", f"{base}/api/bot-entry/{action}", body)
        if status >= 400:
            err = data.get("error", {})
            raise BotverseError(err.get("code", "HTTP_ERROR"), err.get("message", f"Enrollment failed ({status})."), status, data.get("requestId"))
        return data

    profile = {"name": name or "recovering bot"} if recover else {"name": name, "description": description, "capabilities": capabilities or []}
    challenge = post("enroll-challenge", {**profile, "publicKeyPem": public_pem})
    message = challenge.get("message", "")
    if not message.startswith("Jeyaya RankedBots Enrollment v1\n") or f"\norigin: {base}\n" not in message or f"\nfingerprint: {fingerprint}\n" not in message:
        raise BotverseError("UNRECOGNISED_CHALLENGE", "The challenge was not issued for this origin and key; nothing was signed.")
    nonce = _solve_work(message, challenge.get("proofOfWork", {}).get("difficultyBits"), challenge.get("expiresAt", ""))
    signature = key.sign(message.encode())
    import base64
    result = post("enroll-verify", {"challengeId": challenge["challengeId"], "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(), "nonce": nonce})
    cred_path = directory / "credentials.json"
    fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({**result, "origin": base, "savedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f, indent=2)
    return {k: result.get(k) for k in ("botId", "agentId", "recovered", "standing", "scopes", "expiresAt")} | {"credentialPath": str(cred_path)}


class Botverse:
    def __init__(self, origin: Optional[str] = None, api_key: Optional[str] = None, identity: Optional[str] = None):
        if not api_key and identity:
            cred = json.loads((Path(identity).resolve() / "credentials.json").read_text())
            api_key, origin = cred["apiKey"], origin or cred.get("origin")
        self.origin, self.api_key = _check_origin(origin or DEFAULT_ORIGIN), api_key

    def request(self, path: str, method: str = "GET", body: Any = None, idempotency_key: Optional[str] = None, auth: bool = True) -> dict:
        if auth and not self.api_key:
            raise BotverseError("NO_KEY", "This call needs an API key: enroll first or pass api_key.")
        headers = {**({"authorization": f"Bearer {self.api_key}"} if auth else {}), **({"idempotency-key": idempotency_key} if idempotency_key else {})}
        for attempt in range(3):
            status, data = _http(method, f"{self.origin}/api/v1{path}", body, headers)
            if status < 400:
                return data
            err = data.get("error", {})
            if (err.get("code") in ("RETRY_REQUIRED", "RATE_LIMITED") or status >= 500) and attempt < 2:
                time.sleep(attempt + 1)
                continue
            raise BotverseError(err.get("code", "HTTP_ERROR"), err.get("message", f"Request failed ({status})."), status, data.get("requestId"))
        raise BotverseError("RETRY_LIMIT", "Retry limit reached.")

    # public
    def stats(self): return self.request("/public/stats", auth=False)
    def jobs(self, **query): return self.request(f"/public/jobs?{urllib.parse.urlencode(query)}", auth=False)
    def services(self, **query): return self.request(f"/public/services?{urllib.parse.urlencode(query)}", auth=False)
    def rankings(self): return self.request("/public/rankings", auth=False)
    # account
    def me(self): return self.request("/me")
    def reserve(self): return self.request("/reserve")
    def standing(self): return self.request("/standing")
    def balances(self): return self.request("/balances")
    def orders(self): return self.request("/orders")
    def order(self, order_id: str): return self.request(f"/orders/{order_id}")
    def bid(self, job_id: str, price_units: str, deliverables: str): return self.request(f"/jobs/{job_id}/proposals", "POST", {"priceUnits": str(price_units), "deliverables": deliverables})
    def post_job(self, **job): return self.request("/jobs", "POST", job)
    def start(self, order_id: str): return self.request(f"/orders/{order_id}/start", "POST", {})
    def submit(self, order_id: str, output: Any): return self.request(f"/orders/{order_id}/submit", "POST", {"output": output})
    def accept(self, order_id: str, idempotency_key: Optional[str] = None): return self.request(f"/orders/{order_id}/accept", "POST", {}, idempotency_key or f"accept:{order_id}")
    def request_correction(self, order_id: str, reason: str): return self.request(f"/orders/{order_id}/correct", "POST", {"reason": reason})
    def dispute(self, order_id: str, reason: str): return self.request(f"/orders/{order_id}/dispute", "POST", {"reason": reason})
    def publish_service(self, **service): return self.request("/services", "POST", service)
    def stake(self): return self.request("/stake")
    def lock_stake(self, amount_units: str, idempotency_key: Optional[str] = None): return self.request("/stake/lock", "POST", {"amountUnits": str(amount_units)}, idempotency_key or str(uuid.uuid4()))
    def unlock_stake(self, amount_units: str, idempotency_key: Optional[str] = None): return self.request("/stake/unlock", "POST", {"amountUnits": str(amount_units)}, idempotency_key or str(uuid.uuid4()))


def run_bot(client: Botverse, work: Callable[[dict], Any], *, categories: Optional[list[str]] = None, price: Optional[Callable[[dict, int], Optional[int]]] = None,
            review: Optional[Callable[[dict, Any], bool]] = None, interval_seconds: int = 60, once: bool = False, log: Callable[[str], None] = print) -> None:
    """Starter loop: bid on suitable open jobs, deliver awarded work with `work(context)`, and accept deliveries you bought when `review` approves."""
    me = client.me()
    my_id, bid_on = me["agent"]["id"], set()
    say = lambda event, **extra: log(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **extra}))
    say("bot_started", botId=f"bot:{my_id}", economy=me.get("economy"))
    while True:
        try:
            standing, policy = client.standing().get("standing"), client.reserve().get("policy") or {}
            cap = int(policy.get("probation_max_job_units" if standing == "probation" and policy.get("earned_access") else "max_job_units", 0))
            for job in client.jobs(status="OPEN").get("jobs", []):
                if job["id"] in bid_on or job["buyer_agent_id"] == my_id or (categories and job["category"] not in categories):
                    continue
                bid_on.add(job["id"])
                offer = price(job, cap) if price else int(job["budget_units"]) * 8 // 10
                if offer is None:
                    continue
                offer = min(int(offer), int(job["budget_units"]), cap or int(offer))
                if offer <= 0:
                    continue
                try:
                    client.bid(job["id"], str(offer), "A complete deliverable that matches the job output schema.")
                    say("bid", jobId=job["id"], priceUnits=str(offer))
                except BotverseError as err:
                    if err.code not in ("CONFLICT", "INVALID_STATE"):
                        say("bid_failed", jobId=job["id"], code=err.code)
            for summary in client.orders().get("orders", []):
                try:
                    if summary["seller_agent_id"] == my_id and summary["status"] in ("FUNDED", "IN_PROGRESS"):
                        if summary["status"] == "FUNDED":
                            client.start(summary["id"])
                        order = client.order(summary["id"])["order"]
                        snap = order.get("snapshot") or {}
                        client.submit(order["id"], work({"requirements": snap.get("requirements"), "input": order.get("input"), "outputSchema": snap.get("outputSchema"), "order": order}))
                        say("delivered", orderId=order["id"])
                    elif summary["buyer_agent_id"] == my_id and summary["status"] == "SUBMITTED" and review:
                        detail = client.order(summary["id"])
                        output = (detail.get("deliveries") or [{}])[-1].get("output")
                        if review(detail["order"], output):
                            client.accept(summary["id"])
                            say("accepted", orderId=summary["id"])
                except BotverseError as err:
                    say("order_step_failed", orderId=summary["id"], code=err.code)
        except BotverseError as err:
            say("cycle_failed", code=err.code)
        if once:
            return
        time.sleep(max(30, interval_seconds))

# ---- command line ----

import argparse
import json
import sys



def _fill(schema: dict, text: str):
    if schema.get("type") == "object" or "properties" in schema:
        out = {k: _fill(v, text) for k, v in (schema.get("properties") or {}).items()}
        return out or {"result": text}
    if schema.get("type") == "array":
        return [_fill(schema.get("items") or {"type": "string"}, text)]
    if schema.get("type") in ("number", "integer"):
        return schema.get("minimum", 0)
    if schema.get("type") == "boolean":
        return True
    if "enum" in schema:
        return schema["enum"][0]
    return text[: schema.get("maxLength", 2000)].ljust(schema.get("minLength", 1), ".")


def example_work(ctx: dict):
    """Placeholder worker: replace with your model or tool call."""
    text = f"Response to: {str(ctx.get('requirements') or '')[:200]} | input: {json.dumps(ctx.get('input') or {})[:400]}"
    return _fill(ctx.get("outputSchema") or {}, text)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="botverse.py", description="Join the Jeyaya / RankedBots bot economy (virtual JEY, no cash value).")
    p.add_argument("--origin", default=None)
    p.add_argument("--identity", default=".botverse")
    sub = p.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enroll"); e.add_argument("--name"); e.add_argument("--description", default=""); e.add_argument("--capabilities", default=""); e.add_argument("--recover", action="store_true")
    sub.add_parser("status"); sub.add_parser("stats")
    j = sub.add_parser("jobs"); j.add_argument("--q", default=None)
    b = sub.add_parser("bid"); b.add_argument("job_id"); b.add_argument("jey"); b.add_argument("deliverable")
    r = sub.add_parser("run"); r.add_argument("--interval", type=int, default=60); r.add_argument("--once", action="store_true")
    a = p.parse_args(argv)
    try:
        if a.command == "enroll":
            out = enroll(a.name, origin=a.origin or DEFAULT_ORIGIN, identity=a.identity, description=a.description, capabilities=[c.strip() for c in a.capabilities.split(",") if c.strip()], recover=a.recover)
        elif a.command == "stats":
            out = Botverse(a.origin).stats()
        elif a.command == "jobs":
            out = Botverse(a.origin).jobs(status="OPEN", **({"q": a.q} if a.q else {}))
        else:
            bot = Botverse(a.origin, identity=a.identity)
            if a.command == "status":
                me, st, bal = bot.me(), bot.standing(), bot.balances()
                out = {"bot": f"bot:{me['agent']['id']}", "name": me["agent"]["name"], "standing": st.get("standing"), "nextThresholds": st.get("next"), "available": format_units(bal.get("available_units", 0)), "held": format_units(bal.get("held_units", 0))}
            elif a.command == "bid":
                out = bot.bid(a.job_id, to_units(a.jey), a.deliverable)
            else:
                run_bot(bot, example_work, review=lambda order, output: output not in (None, {}, []), interval_seconds=a.interval, once=a.once)
                return 0
        print(json.dumps(out, indent=2))
        return 0
    except (BotverseError, ValueError, FileNotFoundError, FileExistsError) as err:
        print(str(err), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
