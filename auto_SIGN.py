#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram 自动签到（GitHub Actions 友好版）

修复点（本次重点）：
- 解决“发了 /code 验证码但脚本不往下走”的问题：
  1) Telegram 消息可能包含零宽字符/方向符/特殊空格，导致严格正则 match 失败
  2) /code@BotName 12345、"123 45"、"123-45" 等格式需要更鲁棒的解析
- 现在会对收到的消息做 NFKC 归一化 + 清理零宽字符，然后从文本中提取 5~8 位数字作为验证码
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

import requests
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError
from telethon.errors.rpcerrorlist import PhoneCodeInvalidError, PasswordHashInvalidError
from telethon.sessions import StringSession


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log(msg: str) -> None:
    print(f"[{_now()}] {msg}", flush=True)


def redact_text(text: str) -> str:
    """尽量减少日志中的敏感信息：数字打码，最长 200 字符。"""
    if text is None:
        return ""
    masked = re.sub(r"\d", "*", str(text))
    return masked[:200]


def redact_id(value: str) -> str:
    """ID 仅展示后 4 位（其余打码），避免把 chat_id/user_id 直接打到日志里。"""
    s = str(value or "").strip()
    if not s:
        return ""
    sign = "-" if s.startswith("-") else ""
    digits = re.sub(r"\D", "", s)
    if not digits:
        return "***"
    if len(digits) <= 4:
        return sign + ("*" * len(digits))
    return sign + ("*" * (len(digits) - 4)) + digits[-4:]


def digits_to_ascii(text: str) -> str:
    """
    提取 text 中的所有数字并规范化为 ASCII '0'-'9'。
    兼容全角数字/其它 Unicode 数字字符。
    """
    out: List[str] = []
    for ch in re.findall(r"\d", str(text)):
        try:
            out.append(str(unicodedata.digit(ch)))
        except Exception:
            out.append(ch)
    return "".join(out)


# 常见“不可见字符/方向控制符/零宽字符”
_ZERO_WIDTH_CHARS = [
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u200e",  # LRM
    "\u200f",  # RLM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi controls
    "\ufeff",  # BOM / ZERO WIDTH NO-BREAK SPACE
]
_ZERO_WIDTH_TRANSLATE = {ord(ch): None for ch in _ZERO_WIDTH_CHARS}


def normalize_msg(text: str) -> str:
    """
    对 Telegram 消息做归一化，避免因为不可见字符导致正则/解析失败。
    - NFKC：把全角数字/全角空格等归一化
    - 删除零宽/方向字符
    - 替换不间断空格
    """
    t = text or ""
    t = unicodedata.normalize("NFKC", t)
    t = t.translate(_ZERO_WIDTH_TRANSLATE)
    t = t.replace("\u00a0", " ")
    return t.strip()


def env(name: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    val = os.environ.get(name, default)
    if required and (val is None or str(val).strip() == ""):
        raise RuntimeError(f"缺少环境变量：{name}")
    return val


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_delay_range() -> Tuple[float, float]:
    """
    SIGN_DELAY_RANGE 支持：
    - "0.5,2"
    - "0.5-2"
    不配置则默认 1~3 秒
    """
    raw = os.environ.get("SIGN_DELAY_RANGE", "").strip()
    if not raw:
        return (1.0, 3.0)
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*[,|-]\s*(\d+(?:\.\d+)?)\s*$", raw)
    if not m:
        raise RuntimeError("SIGN_DELAY_RANGE 格式错误，示例：1,3 或 1-3")
    a = float(m.group(1))
    b = float(m.group(2))
    if a < 0 or b < 0 or b < a:
        raise RuntimeError("SIGN_DELAY_RANGE 需满足 0<=min<=max")
    return (a, b)


@dataclass(frozen=True)
class SignTask:
    chat: str
    text: str


class BotInteractor:
    """通过 Telegram Bot API 与你交互：发提示、收验证码、收 /pwd。"""

    def __init__(
        self,
        token: str,
        admin_chat_id: str,
        *,
        auto_delete_webhook: bool = False,
        debug_updates: bool = True,
        accept_any: bool = False,
    ):
        self.token = token
        admin_chat_id = str(admin_chat_id).strip()
        admin_ids_ordered: List[str] = []
        seen: set[str] = set()
        for s in re.split(r"[,\s;]+", admin_chat_id):
            s = s.strip()
            if not s or s in seen:
                continue
            seen.add(s)
            admin_ids_ordered.append(s)
        self.admin_ids = set(admin_ids_ordered)
        if not admin_ids_ordered:
            raise RuntimeError("TG_ADMIN_CHAT_ID 为空")
        self.primary_admin_chat_id = admin_ids_ordered[0]
        self.base = f"https://api.telegram.org/bot{self.token}"
        self.auto_delete_webhook = auto_delete_webhook
        self.debug_updates = debug_updates
        self.accept_any = accept_any
        self._webhook_checked = False

    def send(self, text: str) -> None:
        try:
            requests.post(
                f"{self.base}/sendMessage",
                data={"chat_id": self.primary_admin_chat_id, "text": text},
                timeout=30,
            )
            if self.debug_updates:
                log(f"DEBUG send -> chat_id={redact_id(self.primary_admin_chat_id)}: {redact_text(text)!r}")
        except Exception:
            pass

    def _ensure_polling_ready(self) -> None:
        """
        Bot API 的 getUpdates 与 webhook 互斥：
        如果 bot 设置了 webhook，则 getUpdates 会一直收不到消息
        """
        if self._webhook_checked:
            return
        self._webhook_checked = True

        r = requests.get(f"{self.base}/getWebhookInfo", timeout=15)
        data = r.json()
        if not data.get("ok"):
            return
        info = data.get("result") or {}
        url = (info.get("url") or "").strip()
        if not url:
            return

        if not self.auto_delete_webhook:
            raise RuntimeError(
                "检测到你的 TG_BOT_TOKEN 已设置 webhook，getUpdates 无法收验证码。\n"
                "解决：换一个专用 bot，或先关闭 webhook（或设置 TG_DELETE_WEBHOOK=1 让脚本自动关闭）。"
            )

        log("检测到 webhook 已启用，正在 deleteWebhook…")
        requests.post(
            f"{self.base}/deleteWebhook",
            data={"drop_pending_updates": True},
            timeout=20,
        )
        log("deleteWebhook 已执行")

    def flush_offset(self) -> int:
        """把当前 backlog 的 update_id 吃掉，返回下一个 offset。"""
        self._ensure_polling_ready()
        try:
            r = requests.get(f"{self.base}/getUpdates", params={"timeout": 0}, timeout=15)
            data = r.json()
            if data.get("ok") and data.get("result"):
                return int(data["result"][-1]["update_id"]) + 1
        except Exception:
            pass
        return 0

    def _from_admin(self, chat_id: str, from_user_id: str) -> bool:
        if self.accept_any:
            return True
        # 允许两种：
        # - 私聊：chat_id == from_user_id == 你的 user_id
        # - 群聊：chat_id 是群 id（负数），from_user_id 是你的 user_id
        return (chat_id in self.admin_ids) or (from_user_id in self.admin_ids)

    def _extract_login_code(self, text: str, min_len: int = 5, max_len: int = 8) -> Optional[str]:
        """
        从文本中提取 Telegram 登录验证码（5~8 位）。
        支持：
        - 直接发：12345
        - /code 12345
        - /code@BotName 12 345
        - 12-345 等带分隔符
        - 含零宽字符（normalize_msg 已清理）
        """
        t = normalize_msg(text)

        # 去掉常见命令前缀（可选）
        t2 = re.sub(r"^\s*/?(?:code)(?:@\w+)?\b", "", t, flags=re.I).strip()

        # 把文本中的所有数字提出来（兼容全角数字）
        groups = re.findall(r"\d+", t2)
        groups_ascii = [digits_to_ascii(g) for g in groups if g]
        # 优先：存在单段 5~8 位连续数字
        for g in reversed(groups_ascii):
            if min_len <= len(g) <= max_len:
                return g

        # 次优：把多段拼接（比如 12 345 或 12-345）
        merged = "".join(groups_ascii)
        if min_len <= len(merged) <= max_len:
            return merged

        # 再次尝试：在原始文本（含命令）里找
        groups2 = re.findall(r"\d+", t)
        groups2_ascii = [digits_to_ascii(g) for g in groups2 if g]
        for g in reversed(groups2_ascii):
            if min_len <= len(g) <= max_len:
                return g
        merged2 = "".join(groups2_ascii)
        if min_len <= len(merged2) <= max_len:
            return merged2

        return None

    def wait_login_code(self, timeout: int, *, offset: Optional[int] = None) -> Optional[str]:
        """等待验证码（5~8 位），只接受来自 TG_ADMIN_CHAT_ID 的消息。"""
        self._ensure_polling_ready()
        offset = self.flush_offset() if offset is None else int(offset)

        deadline = time.time() + timeout
        last_heartbeat = 0.0

        while time.time() < deadline:
            try:
                r = requests.get(
                    f"{self.base}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                    timeout=35,
                )
                data = r.json()
                if not data.get("ok"):
                    desc = str(data.get("description") or "").strip()
                    if desc:
                        if "Conflict" in desc or "webhook" in desc.lower():
                            raise RuntimeError(
                                "Telegram Bot getUpdates 失败："
                                f"{desc}\n"
                                "可能原因：同一个 TG_BOT_TOKEN 正被其它程序拉取更新，或 webhook 未关闭。\n"
                                "解决：停掉其它实例/删除 webhook（或换一个专用 bot）。"
                            )
                        log(f"Telegram Bot getUpdates 返回错误：{desc}")
                    time.sleep(2)
                    continue

                for upd in data.get("result", []):
                    offset = int(upd["update_id"]) + 1
                    msg = (
                        upd.get("message")
                        or upd.get("edited_message")
                        or upd.get("channel_post")
                        or upd.get("edited_channel_post")
                        or {}
                    )
                    chat = msg.get("chat") or {}
                    chat_id = str(chat.get("id") or "").strip()
                    from_user = msg.get("from") or {}
                    from_user_id = str(from_user.get("id") or "").strip()
                    text = (msg.get("text") or "").strip()

                    if self.debug_updates:
                        log(
                            "DEBUG update: "
                            f"chat_id={redact_id(chat_id)} "
                            f"from_id={redact_id(from_user_id)} "
                            f"text={redact_text(text)!r}"
                        )

                    if not self._from_admin(chat_id, from_user_id):
                        # 如果看起来像验证码/命令，给个提示，方便排查 TG_ADMIN_CHAT_ID 配置
                        if re.search(r"\d", text) or text.strip().startswith("/code"):
                            log(
                                "收到疑似验证码消息，但来源 ID 不匹配："
                                f"chat_id={redact_id(chat_id)} from_id={redact_id(from_user_id)}"
                                "（请检查 TG_ADMIN_CHAT_ID，或临时设置 TG_ACCEPT_ANY=1 排查）"
                            )
                        continue

                    code = self._extract_login_code(text)
                    if code:
                        return code

                    if self.debug_updates:
                        # 明确告诉你“收到了，但没解析出来”
                        norm = normalize_msg(text)
                        log(f"DEBUG 收到消息但无法解析出 5-8 位验证码：{redact_text(norm)!r}")

            except RuntimeError:
                raise
            except Exception:
                pass

            now = time.time()
            if self.debug_updates and (now - last_heartbeat) > 20:
                log(f"DEBUG waiting code ... offset={offset}")
                last_heartbeat = now

            time.sleep(1)

        return None

    def wait_password(self, timeout: int, *, offset: Optional[int] = None) -> Optional[str]:
        """等待 /pwd xxx（2FA 密码）"""
        self._ensure_polling_ready()
        offset = self.flush_offset() if offset is None else int(offset)
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                r = requests.get(
                    f"{self.base}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                    timeout=35,
                )
                data = r.json()
                if not data.get("ok"):
                    time.sleep(2)
                    continue

                for upd in data.get("result", []):
                    offset = int(upd["update_id"]) + 1
                    msg = upd.get("message") or upd.get("edited_message") or {}
                    chat = msg.get("chat") or {}
                    chat_id = str(chat.get("id") or "").strip()
                    from_user = msg.get("from") or {}
                    from_user_id = str(from_user.get("id") or "").strip()
                    text = (msg.get("text") or "").strip()

                    if self.debug_updates:
                        log(
                            "DEBUG update: "
                            f"chat_id={redact_id(chat_id)} "
                            f"from_id={redact_id(from_user_id)} "
                            f"text={redact_text(text)!r}"
                        )

                    if not self._from_admin(chat_id, from_user_id):
                        continue

                    t = normalize_msg(text)
                    m = re.match(r"^/pwd(?:@\w+)?\s*(.*)$", t)
                    if m:
                        pwd = (m.group(1) or "").strip()
                        if pwd:
                            return pwd
            except Exception:
                pass

            time.sleep(1)

        return None


class GitHubSecretUpdater:
    """把 TG_SESSION 写回到仓库 Secrets（需要 REPO_TOKEN）。"""

    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.base = f"https://api.github.com/repos/{self.repo}/actions/secrets"
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json",
        }

    def update_secret(self, name: str, value: str) -> bool:
        try:
            from nacl import encoding, public  # type: ignore
        except Exception as e:
            log(f"缺少依赖 PyNaCl，无法加密写入 Secret：{e}")
            return False

        try:
            r = requests.get(f"{self.base}/public-key", headers=self.headers, timeout=30)
            if r.status_code != 200:
                log(f"获取仓库公钥失败：HTTP {r.status_code} {r.text[:200]}")
                return False
            key_data = r.json()
            key_id = key_data["key_id"]
            key = key_data["key"]

            pk = public.PublicKey(key.encode("utf-8"), encoding.Base64Encoder())
            sealed_box = public.SealedBox(pk)
            encrypted = sealed_box.encrypt(value.encode("utf-8"))
            encrypted_b64 = encoding.Base64Encoder.encode(encrypted).decode("utf-8")

            payload = {"encrypted_value": encrypted_b64, "key_id": key_id}
            put = requests.put(f"{self.base}/{name}", headers=self.headers, json=payload, timeout=30)
            if put.status_code not in (201, 204):
                log(f"写入 Secret 失败：HTTP {put.status_code} {put.text[:200]}")
                return False
            return True
        except Exception as e:
            log(f"写入 Secret 异常：{e}")
            return False


def parse_tasks(raw: str) -> List[SignTask]:
    raw = (raw or "").strip()
    if not raw:
        raise RuntimeError("TG_SIGN_TASKS 为空")

    if raw.startswith("{") or raw.startswith("["):
        data = json.loads(raw)
        items = data.get("tasks") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise RuntimeError("TG_SIGN_TASKS JSON 需为数组，或 {\"tasks\": [...]}")
        tasks: List[SignTask] = []
        for i, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                raise RuntimeError(f"TG_SIGN_TASKS 第{i}项不是对象")
            chat = str(item.get("chat") or item.get("chat_id") or item.get("to") or "").strip()
            text = str(item.get("text") or item.get("message") or "").strip()
            if not chat or not text:
                raise RuntimeError(f"TG_SIGN_TASKS 第{i}项缺少 chat/text")
            tasks.append(SignTask(chat=chat, text=text))
        return tasks

    chunks = []
    for part in re.split(r"[;\n]+", raw):
        line = part.strip()
        if not line or line.startswith("#"):
            continue
        chunks.append(line)

    tasks2: List[SignTask] = []
    for i, line in enumerate(chunks, start=1):
        sep = None
        for candidate in ("|", ",", ":"):
            if candidate in line:
                sep = candidate
                break
        if not sep:
            raise RuntimeError(f"TG_SIGN_TASKS 第{i}项格式不支持：{line!r}（请用 chat|text）")
        chat, text = line.split(sep, 1)
        chat = chat.strip()
        text = text.strip()
        if not chat or not text:
            raise RuntimeError(f"TG_SIGN_TASKS 第{i}项 chat/text 为空：{line!r}")
        tasks2.append(SignTask(chat=chat, text=text))
    return tasks2


async def ensure_login(
    client: TelegramClient,
    phone_number: str,
    bot: Optional[BotInteractor],
    code_timeout: int,
    password: Optional[str],
    allow_print_session: bool,
    updater: Optional[GitHubSecretUpdater],
) -> str:
    """确保已登录，返回 session string。"""
    await client.connect()
    if await client.is_user_authorized():
        return client.session.save()

    if bot is None and not sys.stdin.isatty():
        raise RuntimeError("首次登录需要 TG_BOT_TOKEN + TG_ADMIN_CHAT_ID（Actions 环境无交互输入）")

    log("未检测到授权，开始登录流程…")
    log("正在向 Telegram 请求登录验证码（send_code_request）…")
    sent = await client.send_code_request(phone_number)

    log("验证码已发送（请在 Telegram App/SMS 查看）。")
    log("请把验证码发给机器人：直接发送数字（例如 12345），或发送 /code 12345")

    code: Optional[str] = None
    if bot is not None:
        offset = bot.flush_offset()
        bot.send(
            "需要 Telegram 登录验证码。\n"
            f"请在 {code_timeout}s 内回复：直接发送验证码数字（例如 12345），或 /code 12345\n"
            "（只接受来自 TG_ADMIN_CHAT_ID 的消息）"
        )
        log(f"已发送提示到 Telegram，等待验证码（最长 {code_timeout}s）…")
        code = bot.wait_login_code(timeout=code_timeout, offset=offset)
    else:
        code = input("请输入 Telegram 登录验证码：").strip()

    if not code:
        raise RuntimeError(
            "未收到有效验证码（5-8 位数字），登录失败。\n"
            "排查建议：\n"
            "1) 确认你是在收到提示的同一个聊天窗口回复（私聊/群）。\n"
            "2) 检查 TG_ADMIN_CHAT_ID：私聊=你的 user_id；群里=群 chat_id（-100...）。\n"
            "3) 若同一 bot 同时被其它服务拉取更新，或 webhook 未关闭：设置 TG_DELETE_WEBHOOK=1 或换专用 bot。\n"
            "4) 可临时设置 TG_ACCEPT_ANY=1 验证是否是 ID 过滤导致。"
        )

    log(f"已收到验证码：{redact_text(code)!r}，开始 sign_in…")
    try:
        await client.sign_in(phone_number, code, phone_code_hash=sent.phone_code_hash)
    except PhoneCodeInvalidError:
        raise RuntimeError("验证码错误（PhoneCodeInvalidError）") from None
    except SessionPasswordNeededError:
        if not password and bot is not None:
            bot.send("检测到开启了两步验证(2FA)。请回复：/pwd 你的密码")
            log(f"等待 /pwd（最长 {code_timeout}s）…")
            password = bot.wait_password(timeout=code_timeout)

        if not password and sys.stdin.isatty():
            password = input("请输入两步验证(2FA)密码：").strip()

        if not password:
            raise RuntimeError("需要 2FA 密码，但未提供 TG_2FA_PASSWORD 或 /pwd")

        try:
            await client.sign_in(password=password)
        except PasswordHashInvalidError:
            raise RuntimeError("2FA 密码错误（PasswordHashInvalidError）") from None

    session_str = client.session.save()

    if updater is not None:
        ok = updater.update_secret("TG_SESSION", session_str)
        if ok:
            log("已自动写回 GitHub Secrets：TG_SESSION")
            if bot is not None:
                bot.send("✅ Telegram 登录成功，已自动写回仓库 Secrets：TG_SESSION")
        else:
            log("自动写回 TG_SESSION 失败（请检查 REPO_TOKEN 权限 / PyNaCl 安装）")
            if bot is not None:
                bot.send("⚠️ 登录成功，但自动写回 TG_SESSION 失败，请查看 Actions 日志")
    else:
        if allow_print_session:
            log("TG_SESSION（请复制到 GitHub Secrets：TG_SESSION）：")
            print(session_str, flush=True)
        else:
            raise RuntimeError("登录成功但无法持久化：请配置 REPO_TOKEN 自动写回，或设置 PRINT_SESSION=1 手动复制")

    return session_str


async def run_sign(client: TelegramClient, tasks: List[SignTask], delay_range: Tuple[float, float]) -> Tuple[int, int]:
    ok = 0
    fail = 0

    for idx, task in enumerate(tasks, start=1):
        try:
            target: Any = task.chat
            if re.fullmatch(r"-?\d+", task.chat):
                target = int(task.chat)
            entity = await client.get_input_entity(target)
            await client.send_message(entity, task.text)
            ok += 1
            chat_show = redact_id(task.chat) if re.fullmatch(r"-?\d+", task.chat) else task.chat
            log(f"[{idx}/{len(tasks)}] 已发送 -> {chat_show}: {redact_text(task.text)[:60]!r}")
        except FloodWaitError as e:
            wait_s = int(getattr(e, "seconds", 0) or 0)
            log(f"[{idx}/{len(tasks)}] 触发 FloodWait，等待 {wait_s}s 后重试…")
            await asyncio.sleep(max(wait_s, 1))
            try:
                target2: Any = task.chat
                if re.fullmatch(r"-?\d+", task.chat):
                    target2 = int(task.chat)
                entity = await client.get_input_entity(target2)
                await client.send_message(entity, task.text)
                ok += 1
                chat_show = redact_id(task.chat) if re.fullmatch(r"-?\d+", task.chat) else task.chat
                log(f"[{idx}/{len(tasks)}] 重试成功 -> {chat_show}")
            except Exception as e2:
                fail += 1
                chat_show = redact_id(task.chat) if re.fullmatch(r"-?\d+", task.chat) else task.chat
                log(f"[{idx}/{len(tasks)}] 重试失败 -> {chat_show}: {e2}")
        except Exception as e:
            fail += 1
            chat_show = redact_id(task.chat) if re.fullmatch(r"-?\d+", task.chat) else task.chat
            log(f"[{idx}/{len(tasks)}] 发送失败 -> {chat_show}: {e}")

        if idx != len(tasks):
            sleep_s = random.uniform(delay_range[0], delay_range[1])
            await asyncio.sleep(sleep_s)

    return ok, fail


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Telegram 自动签到（GitHub Actions）")
    p.add_argument("--login-only", action="store_true", help="仅完成登录/写回 TG_SESSION，不发送签到消息")
    return p


async def async_main(args: argparse.Namespace) -> int:
    api_id = int(env("TG_API_ID", required=True))
    api_hash = env("TG_API_HASH", required=True)
    phone_number = env("TG_PHONE_NUMBER", required=True)

    tasks: List[SignTask] = []
    if not args.login_only:
        raw_tasks = env("TG_SIGN_TASKS", required=True) or ""
        tasks = parse_tasks(raw_tasks)
    else:
        raw_tasks = (env("TG_SIGN_TASKS") or "").strip()
        if raw_tasks:
            tasks = parse_tasks(raw_tasks)

    session_str = (env("TG_SESSION") or "").strip()
    allow_print_session = env_bool("PRINT_SESSION", default=False)
    code_timeout = int(env("TG_LOGIN_TIMEOUT", default="300") or "300")

    bot_token = (env("TG_BOT_TOKEN") or "").strip()
    admin_chat_id = (env("TG_ADMIN_CHAT_ID") or "").strip()
    auto_delete_webhook = env_bool("TG_DELETE_WEBHOOK", default=False)
    debug_updates = env_bool("TG_DEBUG_UPDATES", default=True)
    accept_any = env_bool("TG_ACCEPT_ANY", default=False)

    bot: Optional[BotInteractor] = None
    if bot_token and admin_chat_id:
        bot = BotInteractor(
            bot_token,
            admin_chat_id,
            auto_delete_webhook=auto_delete_webhook,
            debug_updates=debug_updates,
            accept_any=accept_any,
        )

    password = (env("TG_2FA_PASSWORD") or "").strip() or None

    repo_token = (env("REPO_TOKEN") or "").strip()
    repo = (env("GITHUB_REPOSITORY") or "").strip()
    updater: Optional[GitHubSecretUpdater] = None
    if repo_token and repo:
        updater = GitHubSecretUpdater(repo_token, repo)

    delay_range = parse_delay_range()

    client = TelegramClient(StringSession(session_str or None), api_id, api_hash)
    try:
        _ = await ensure_login(
            client=client,
            phone_number=phone_number,
            bot=bot,
            code_timeout=code_timeout,
            password=password,
            allow_print_session=allow_print_session,
            updater=updater,
        )

        if args.login_only:
            log("login-only 模式：结束")
            return 0

        ok, fail = await run_sign(client, tasks, delay_range=delay_range)
        summary = f"✅ 签到任务完成：成功 {ok} / 失败 {fail}"
        log(summary)
        if bot is not None:
            bot.send(summary)
        return 0 if fail == 0 else 2
    finally:
        await client.disconnect()


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        return asyncio.run(async_main(args))
    except Exception as e:
        log(f"ERROR: {e}")
        bot_token = (os.environ.get("TG_BOT_TOKEN") or "").strip()
        admin_chat_id = (os.environ.get("TG_ADMIN_CHAT_ID") or "").strip()
        if bot_token and admin_chat_id:
            try:
                BotInteractor(bot_token, admin_chat_id).send(f"❌ AUTO_SIGN 失败：{e}")
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())