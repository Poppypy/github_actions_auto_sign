#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram 自动签到（GitHub Actions 友好版）

功能：
- 使用 Telethon 以“用户号”给多个 chat/bot 发送签到消息
- 配置全部来自 GitHub Secrets / Variables（环境变量）
- 首次无 TG_SESSION 时：通过 Telegram 机器人交互收验证码（/code 12345）
  可选：用 REPO_TOKEN 自动写回 TG_SESSION 到 GitHub Secrets，后续无需再登录

环境变量（建议放到 GitHub Secrets / Variables）：
必需（用户号登录）：
- TG_API_ID
- TG_API_HASH
- TG_PHONE_NUMBER

必需（发送签到目标）：
- TG_SIGN_TASKS：JSON（推荐）或 文本列表

可选（免登录）：
- TG_SESSION：Telethon StringSession 字符串

可选（首次登录机器人交互）：
- TG_BOT_TOKEN：用于交互的 Telegram Bot Token
- TG_ADMIN_CHAT_ID：你与机器人对话的 chat_id（只接受该 chat 发来的 /code、/pwd）

可选（两步验证 2FA）：
- TG_2FA_PASSWORD：如果没配，会要求你在机器人里发 /pwd xxxxx

可选（自动写回 Secret）：
- REPO_TOKEN：GitHub PAT（需要能写 Actions secrets）
  脚本会尝试把新生成的 TG_SESSION 写回到仓库 Secrets（名称 TG_SESSION）
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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError
from telethon.errors.rpcerrorlist import PhoneCodeInvalidError, PasswordHashInvalidError
from telethon.sessions import StringSession


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log(msg: str) -> None:
    print(f"[{_now()}] {msg}", flush=True)


def env(name: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    val = os.environ.get(name, default)
    if required and (val is None or str(val).strip() == ""):
        raise RuntimeError(f"缺少环境变量：{name}")
    return val


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
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
    """通过 Telegram Bot API 与你交互：发提示、收 /code、收 /pwd。"""

    def __init__(self, token: str, admin_chat_id: str, *, auto_delete_webhook: bool = False):
        self.token = token
        self.admin_chat_id = str(admin_chat_id)
        self.base = f"https://api.telegram.org/bot{self.token}"
        self.auto_delete_webhook = auto_delete_webhook
        self._webhook_checked = False

    def send(self, text: str) -> None:
        try:
            requests.post(
                f"{self.base}/sendMessage",
                data={"chat_id": self.admin_chat_id, "text": text},
                timeout=30,
            )
        except Exception:
            pass

    def _ensure_polling_ready(self) -> None:
        """
        Bot API 的 getUpdates 与 webhook 互斥：
        - 如果 bot 设置了 webhook，则 getUpdates 会一直收不到消息
        这里做一次检查，并在允许时自动 deleteWebhook。
        """
        if self._webhook_checked:
            return
        self._webhook_checked = True

        try:
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
            try:
                requests.post(
                    f"{self.base}/deleteWebhook",
                    data={"drop_pending_updates": True},
                    timeout=20,
                )
                log("deleteWebhook 已执行")
            except Exception as e:
                raise RuntimeError(f"deleteWebhook 失败：{e}") from None
        except Exception:
            raise

    def flush_offset(self) -> int:
        self._ensure_polling_ready()
        try:
            r = requests.get(f"{self.base}/getUpdates", params={"timeout": 0}, timeout=15)
            data = r.json()
            if data.get("ok") and data.get("result"):
                return int(data["result"][-1]["update_id"]) + 1
        except Exception:
            pass
        return 0

    def wait_command(self, pattern: "re.Pattern[str]", timeout: int, *, offset: Optional[int] = None) -> Optional[str]:
        """
        仅接收来自 TG_ADMIN_CHAT_ID 的 message.text。
        返回 pattern 捕获组 1。
        """
        self._ensure_polling_ready()
        offset = self.flush_offset() if offset is None else int(offset)
        deadline = time.time() + timeout
        last_desc: str = ""
        last_desc_ts = 0.0

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
                        # 这类问题通常不会“等一等就好”，直接报错更友好
                        if "Conflict" in desc or "webhook" in desc.lower():
                            raise RuntimeError(
                                "Telegram Bot getUpdates 失败："
                                f"{desc}\n"
                                "可能原因：该 bot 设置了 webhook，或同一个 TG_BOT_TOKEN 正被其它程序/服务拉取更新。\n"
                                "解决：停掉其它实例/删除 webhook（或换一个专用 bot）。"
                            )
                        # 其它错误：降频打印，避免刷屏
                        now = time.time()
                        if desc != last_desc or (now - last_desc_ts) > 30:
                            log(f"Telegram Bot getUpdates 返回错误：{desc}")
                            last_desc = desc
                            last_desc_ts = now
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
                    if str(chat.get("id")) != self.admin_chat_id:
                        continue

                    text = (msg.get("text") or "").strip()
                    m = pattern.match(text)
                    if m:
                        return m.group(1)
            except RuntimeError:
                raise
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
        if isinstance(data, dict):
            items = data.get("tasks")
        else:
            items = data
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

    # 非 JSON：每行 / 每段一个任务
    # 推荐格式：chat|text
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
    """
    确保已登录，返回 session string（无论是否已有）。
    """
    await client.connect()
    if await client.is_user_authorized():
        return client.session.save()

    if bot is None and not sys.stdin.isatty():
        raise RuntimeError("首次登录需要 TG_BOT_TOKEN + TG_ADMIN_CHAT_ID（Actions 环境无交互输入）")

    log("未检测到授权，开始登录流程…")
    sent = await client.send_code_request(phone_number)

    code: Optional[str] = None
    if bot is not None:
        offset = bot.flush_offset()
        bot.send(
            "需要 Telegram 登录验证码。\n"
            f"请在 {code_timeout}s 内回复：/code 12345\n"
            "（只接受来自 TG_ADMIN_CHAT_ID 的消息）"
        )
        code = bot.wait_command(
            re.compile(r"^/code(?:@\\w+)?\\s+(\\d{5,8})$"),
            timeout=code_timeout,
            offset=offset,
        )
    else:
        code = input("请输入 Telegram 登录验证码：").strip()

    if not code:
        raise RuntimeError("未收到验证码 /code，登录失败")

    try:
        await client.sign_in(phone_number, code, phone_code_hash=sent.phone_code_hash)
    except PhoneCodeInvalidError:
        raise RuntimeError("验证码错误（PhoneCodeInvalidError）") from None
    except SessionPasswordNeededError:
        if not password and bot is not None:
            bot.send("检测到开启了两步验证(2FA)。请回复：/pwd 你的密码")
            password = bot.wait_command(
                re.compile(r"^/pwd(?:@\\w+)?\\s+(.+)$"),
                timeout=code_timeout,
            )

        if not password and sys.stdin.isatty():
            password = input("请输入两步验证(2FA)密码：").strip()

        if not password:
            raise RuntimeError("需要 2FA 密码，但未提供 TG_2FA_PASSWORD 或 /pwd")

        try:
            await client.sign_in(password=password)
        except PasswordHashInvalidError:
            raise RuntimeError("2FA 密码错误（PasswordHashInvalidError）") from None

    session_str = client.session.save()

    # Actions 中尽量不要直接把 session 打到日志里
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
            log(f"[{idx}/{len(tasks)}] 已发送 -> {task.chat}: {task.text[:60]!r}")
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
                log(f"[{idx}/{len(tasks)}] 重试成功 -> {task.chat}")
            except Exception as e2:
                fail += 1
                log(f"[{idx}/{len(tasks)}] 重试失败 -> {task.chat}: {e2}")
        except Exception as e:
            fail += 1
            log(f"[{idx}/{len(tasks)}] 发送失败 -> {task.chat}: {e}")

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
    bot: Optional[BotInteractor] = None
    if bot_token and admin_chat_id:
        bot = BotInteractor(bot_token, admin_chat_id, auto_delete_webhook=auto_delete_webhook)

    password = (env("TG_2FA_PASSWORD") or "").strip() or None

    repo_token = (env("REPO_TOKEN") or "").strip()
    repo = (env("GITHUB_REPOSITORY") or "").strip()
    updater: Optional[GitHubSecretUpdater] = None
    if repo_token and repo:
        updater = GitHubSecretUpdater(repo_token, repo)

    delay_range = parse_delay_range()

    client = TelegramClient(StringSession(session_str or None), api_id, api_hash)
    try:
        # 确保登录（并在需要时写回 TG_SESSION）
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
