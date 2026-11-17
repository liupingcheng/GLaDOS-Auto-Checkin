"""在隔离浏览器中运行官网自身的签到流程，不保存会话、截图或网络跟踪。"""
import hashlib
import math
import os
import re
import time
from urllib.parse import urlsplit


class BrowserFlowError(RuntimeError):
    """只携带固定的脱敏错误文案。"""


def turnstile_error_code(text):
    if "[cloudflare turnstile]" not in text.lower():
        return None
    match = re.search(r"\b(?:error(?: code)?|code):?\s*([0-9]{6})\b", text, re.IGNORECASE)
    return match.group(1) if match else None


def turnstile_response_diagnostics(text):
    codes = set(re.findall(
        r'(?i)["\']?(?:error[ _-]?code|code)["\']?\s*[:=]\s*["\']?((?:110|200|300|400|600)[0-9]{3})\b', text,
    ))
    labels = {label for phrase, label in (
        ("invalid sitekey", "invalid-sitekey"), ("domain not authorized", "domain-not-authorized"),
        ("unsupported browser", "unsupported-browser"), ("bad request", "bad-request"),
    ) if phrase in text.lower()}
    return codes, labels


def browser_cookies(raw, origin):
    cookies = []
    for part in raw.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name and value:
            cookies.append({"name": name, "value": value, "url": origin,
                            "secure": True, "sameSite": "Lax",
                            "httpOnly": name.startswith(("gld:", "koa:"))})
    if not cookies:
        raise BrowserFlowError("浏览器签到缺少会话 Cookie")
    return cookies


def validate_submission(payload, challenge, now):
    """校验官网请求完整性；验证状态如实提交，由服务端作业务判断。"""
    if (not isinstance(payload, dict) or not challenge or
            type(challenge.get("code")) is not int or challenge["code"] != 0):
        raise BrowserFlowError("官网浏览器未取得有效签到验证，已停止提交")
    nonce = challenge.get("nonce")
    ttl = challenge.get("ttl", 300000)
    if (not isinstance(nonce, str) or not nonce.strip() or
            type(ttl) not in (int, float) or not math.isfinite(ttl) or ttl <= 0 or
            now >= challenge["received_at"] + ttl / 1000 - 15):
        raise BrowserFlowError("官网浏览器签到验证无效或过期，已停止提交")
    proof = hashlib.sha256((nonce + ".glados-observe-v1").encode("utf-8")).hexdigest()
    if payload.get("nonce") != nonce or payload.get("proof") != proof:
        raise BrowserFlowError("官网浏览器未生成匹配的 nonce/proof，已停止提交")
    if payload.get("token") != "glados.cloud":
        raise BrowserFlowError("官网浏览器签到域名不匹配，已停止提交")
    if challenge.get("turnstile") not in (None, False):
        state = payload.get("tsState")
        if state == "ok":
            if not isinstance(payload.get("turnstile"), str) or not payload["turnstile"].strip():
                raise BrowserFlowError("官网浏览器未提供对应的验证令牌，已停止提交")
        elif state in ("error", "timeout"):
            # 官网 solveChallenge 也会提交这些真实结果；不得伪造成 ok/off，
            # 也不能在客户端把它等同于服务端已拒绝本次签到。
            if "turnstile" in payload:
                raise BrowserFlowError("官网浏览器验证状态与令牌矛盾，已停止提交")
        else:
            raise BrowserFlowError("官网浏览器验证状态无效，已停止提交")
    elif payload.get("tsState") != "off":
        raise BrowserFlowError("官网浏览器验证状态不一致，已停止提交")


def browser_checkin(headers, checkin_url, challenge_url):
    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError
    except ImportError:
        raise BrowserFlowError("Turnstile 浏览器流程缺少 Playwright/Chromium 依赖") from None

    parsed = urlsplit(checkin_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin != "https://glados.cloud" or challenge_url != checkin_url + "/challenge":
        raise BrowserFlowError("浏览器签到仅允许官网同域接口")
    state = {"challenge": None, "result": None, "error": None, "submitted": False, "secrets": []}
    diagnostics = {"codes": set(), "http": set(), "network": set(), "labels": set(), "state": "未提交"}

    def console(message):
        code = turnstile_error_code(message.text)
        if code:
            diagnostics["codes"].add(code)

    def failed(request):
        if urlsplit(request.url).hostname == "challenges.cloudflare.com":
            match = re.search(r"net::(ERR_[A-Z_]+)", request.failure or "")
            if match:
                diagnostics["network"].add(match.group(1))

    def diagnostic_error(message):
        fields = ["状态=" + diagnostics["state"]]
        for key, label in (("codes", "错误码"), ("http", "HTTP"), ("network", "网络"), ("labels", "分类")):
            if diagnostics[key]:
                fields.append(label + "=" + ",".join(map(str, sorted(diagnostics[key])))[:160])
        return BrowserFlowError(message + "（" + "；".join(fields) + "）")

    def observe(response):
        try:
            if urlsplit(response.url).hostname == "challenges.cloudflare.com" and response.status >= 400:
                diagnostics["http"].add(response.status)
                try:
                    codes, labels = turnstile_response_diagnostics(response.text())
                    diagnostics["codes"].update(codes)
                    diagnostics["labels"].update(labels)
                except Exception:
                    pass  # 可选诊断正文不可读时，不覆盖真正的验证结果。
            if response.url == challenge_url:
                if response.status != 200:
                    state["error"] = "官网浏览器获取签到验证失败"
                else:
                    data = response.json()
                    if isinstance(data, dict):
                        data["received_at"] = time.monotonic()
                        state["challenge"] = data
            elif response.url == checkin_url and response.request.method == "POST":
                if response.status != 200:
                    state["error"] = f"官网浏览器签到接口 HTTP {response.status}"
                else:
                    state["result"] = response.json()
        except Exception:
            state["error"] = "官网浏览器接口未返回有效 JSON"

    def guard(route):
        request = route.request
        previous = request.redirected_from
        if previous and previous.url == checkin_url and previous.method == "POST":
            state["error"] = "官网浏览器签到发生重定向，已停止"
            route.abort()
        elif request.url == checkin_url and request.method == "POST":
            try:
                if state["submitted"]:
                    raise BrowserFlowError("本次浏览器流程已经提交，已阻止重复请求")
                payload = request.post_data_json
                if isinstance(payload, dict) and payload.get("tsState") in ("off", "ok", "error", "timeout"):
                    diagnostics["state"] = payload["tsState"]
                validate_submission(payload, state["challenge"], time.monotonic())
                state["secrets"] = [payload["nonce"], payload["proof"], payload.get("turnstile", "")]
                state["submitted"] = True
                route.continue_()
            except Exception as exc:
                state["error"] = str(exc) if isinstance(exc, BrowserFlowError) else "官网浏览器请求格式无效"
                route.abort()
        elif (urlsplit(request.url).path.startswith("/api/user/") and
              request.method not in ("GET", "HEAD", "OPTIONS")):
            state["error"] = "已阻止签到以外的账号写操作"
            route.abort()
        else:
            route.continue_()

    print("   官网要求浏览器验证，正在运行官网自身的签到页面", flush=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not bool(os.environ.get("DISPLAY")))
            try:
                context = browser.new_context(user_agent=headers["user-agent"], locale="en-US")
                context.add_cookies(browser_cookies(headers["cookie"], origin))
                page = context.new_page()
                page.route("**/*", guard)
                page.on("response", observe)
                page.on("console", console)
                page.on("requestfailed", failed)
                page.goto(origin + "/console/checkin", wait_until="domcontentloaded", timeout=40000)
                if urlsplit(page.url).path != "/console/checkin":
                    raise BrowserFlowError("官网浏览器未进入已登录的签到页")
                button = page.get_by_role("button", name=re.compile(r"^(Checkin|Check in|签到)$"))
                button.click(timeout=25000)
                deadline = time.monotonic() + 100
                while state["result"] is None and state["error"] is None and time.monotonic() < deadline:
                    page.wait_for_timeout(200)
                if state["error"]:
                    raise diagnostic_error(state["error"])
                if not isinstance(state["result"], dict) or not state["submitted"]:
                    raise BrowserFlowError("官网浏览器验证未完成或请求超时；未取得签到结果")
                print("   官网浏览器已提交签到请求（验证状态=" + diagnostics["state"] + "）", flush=True)
                return state["result"], state["secrets"]
            finally:
                browser.close()
    except PlaywrightError:
        raise diagnostic_error(state["error"] or "官网浏览器流程未完成；可能需要人工验证或检查浏览器依赖") from None
