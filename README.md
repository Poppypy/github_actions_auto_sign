# github_action_auto_sign

用 GitHub Actions 定时给 Telegram 的 bot/群/频道发送“签到”消息（支持多个目标）。

核心文件：
- `auto_SIGN.py`：签到脚本（Telethon 用户号发送消息）
- `.github/workflows/TG_LOGIN.yml`：首次登录（机器人交互拿验证码）并自动写回 `TG_SESSION`
- `.github/workflows/AUTO_SIGN.yml`：定时签到

## 1) 需要准备什么

1. 在 `https://my.telegram.org` 申请：
   - `TG_API_ID`
   - `TG_API_HASH`
2. Telegram 手机号：`TG_PHONE_NUMBER`（国际格式，例如 `+86...`）
3. 创建一个“通知机器人”（@BotFather），拿到：
   - `TG_BOT_TOKEN`
4. 获取你和机器人对话的 `chat_id`（也就是你说的“我的对话 id”）：
   - 先给机器人发任意一句话，然后用 Bot API 的 `getUpdates` 能看到 `message.chat.id`
   - 把这个值填到：`TG_ADMIN_CHAT_ID`

## 2) 配置 GitHub Secrets（仓库 Settings → Secrets and variables → Actions）

必填（Secrets）：
- `TG_API_ID`
- `TG_API_HASH`
- `TG_PHONE_NUMBER`
- `TG_BOT_TOKEN`
- `TG_ADMIN_CHAT_ID`

可选（Secrets）：
- `TG_2FA_PASSWORD`：如果你的账号开启了两步验证(2FA)，建议配置；否则脚本会让你在机器人里发 `/pwd 你的密码`
- `TG_SESSION`：Telethon 的 StringSession；**首次运行 `TG_LOGIN` 会自动生成并写回**

强烈推荐（Secrets）：
- `REPO_TOKEN`：GitHub PAT，用于把生成的 `TG_SESSION` 自动写回到仓库 Secrets  
  建议用 **Fine-grained PAT**，只授权当前仓库，并给 `Actions secrets: Read and write` 权限（或等价权限）。

## 3) 配置签到目标（Variables）

在 Variables 里新增：
- `TG_SIGN_TASKS`

推荐用 JSON（支持多个 chat + 多条内容）：

```json
[
  {"chat": "@jdHappybot", "text": "/qd"},
  {"chat": "-1001234567890", "text": "签到"}
]
```

也支持简易文本（用 `;` 或换行分隔，每条用 `chat|text`）：

```
@jdHappybot|/qd
-1001234567890|签到
```

## 4) 首次登录（会通过机器人交互拿验证码）

1. 先确保你已经配置了 `REPO_TOKEN`
2. 在 Actions 页面手动运行工作流：`TG_LOGIN`
3. 机器人会提示你发送：`/code 12345`
4. 成功后会自动写回：Secrets → `TG_SESSION`

常见问题：我已经发了 `/code 12345`，但工作流提示“未收到验证码”
- 你的 bot 可能已经配置过 **webhook**，或者同一个 `TG_BOT_TOKEN` 正被其它程序占用（会导致 `getUpdates` 收不到消息）
  - 最简单：换一个专用 bot token
  - 或者：在仓库 Variables 里加 `TG_DELETE_WEBHOOK=1`，再手动跑一次 `TG_LOGIN`（脚本会尝试自动 `deleteWebhook`）
- 如果你是在群里和 bot 交互，命令可能会变成：`/code@你的机器人用户名 12345`（脚本已兼容）
 - 如果你回复慢，可以在仓库 Variables 里加 `TG_LOGIN_TIMEOUT=600`（单位秒）

## 5) 自动签到

工作流：`AUTO_SIGN`
- 支持 `workflow_dispatch` 手动运行
- 也包含 `schedule` 定时运行（注意 GitHub cron 是 **UTC**）

可选变量：
- `SIGN_DELAY_RANGE`：每条消息之间随机等待（默认 `1-3` 秒），例如 `0.5-2`
