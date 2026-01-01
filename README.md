# github_action_auto_sign

用 GitHub Actions 定时给 Telegram 的 bot/群/频道发送“签到”消息（支持多个目标）。

核心文件：
- `auto_SIGN.py`：签到脚本（Telethon 用户号发送消息）
- `.github/workflows/TG_LOGIN.yml`：首次登录（机器人交互拿验证码）并自动写回 `TG_SESSION`
- `.github/workflows/AUTO_SIGN.yml`：定时签到

## 1) 需要准备什么


先“fork”本仓库



1. 在 `https://my.telegram.org` 申请：
   - `TG_API_ID`
   - `TG_API_HASH`
<details>

第一步 打开官方网址：https://my.telegram.org/  并输入你的电报手机号码 (记得带 + 号) 点击：NEXT  


<img src="png/image.png" alt="登录" width="300">

第二步 这时候你的电报会收到一个 code （复制） 如下图：

<img src="png/image2.png" alt="登录" width="300">

第三步 填写到 code  并点击：Sign IN   如下图：

<img src="png/image3.png" alt="登录" width="300">

第四步 登录成功后  点击：API development tools

<img src="png/image4.png" alt="登录" width="300">


第五步 这时候你会进入一个页面填写：App title  和  Short name   就可以创建一个应用 ID 和 HASH  最终得到图下图

在输入：App title  和  Short name  创建应用时好像很容易报错或失败，请尝试输入不同的 Short name 或者换干净IP多试几次才可以成功

自己记住：api_id  和 api_hash （按对应项目要求填写到对应位置即可）不同的项目源码可能填写的位置不一样

<img src="png/image5.png" alt="登录" width="300">



</details>

2. Telegram 手机号：`TG_PHONE_NUMBER`（国际格式，例如 `+86...`）
3. 创建一个“通知机器人”（@BotFather），拿到：
   - `TG_BOT_TOKEN`
<details>

打开应用  @BotFather 
<img src="png/image6.png" alt="创建机器人" width="300">

点击创建

<img src="png/image7.png" alt="创建机器人" width="300">

<img src="png/image8.png" alt="创建机器人" width="300">

<img src="png/image9.png" alt="创建机器人" width="300">


</details>

4. 获取你和机器人对话的 `chat_id`（也就是你说的“我的对话 id”）：
   - 先给机器人发任意一句话，然后用 Bot API 的 `getUpdates` 能看到 `message.chat.id`
   - 把这个值填到：`TG_ADMIN_CHAT_ID`
<details>
点自己的头像复制ID
<img src="png/image10.png" alt="复制chat_id" width="300">

</details>

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
  {"chat": "@tuoyi03bot", "text": "🌍 每日签到"},
  {"chat": "@jrsgk4_bot", "text": "/checkin"}
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
3. 机器人会提示你发送：直接发送验证码数字（例如 `12345`），或发送：`/code 12345`
4. 成功后会自动写回：Secrets → `TG_SESSION`

常见问题：我已经发了 `/code 12345`，但工作流提示“未收到验证码”
- 你的 bot 可能已经配置过 **webhook**，或者同一个 `TG_BOT_TOKEN` 正被其它程序占用（会导致 `getUpdates` 收不到消息）
  - 最简单：换一个专用 bot token
  - 或者：在仓库 Variables 里加 `TG_DELETE_WEBHOOK=1`，再手动跑一次 `TG_LOGIN`（脚本会尝试自动 `deleteWebhook`）
- `TG_ADMIN_CHAT_ID` 既可以填“私聊 chat_id（=你的 user_id）”，也可以填“群 chat_id（-100...）”；也支持多个（逗号/空格/分号分隔）
- 如果你是在群里和 bot 交互，命令可能会变成：`/code@你的机器人用户名 12345`（脚本已兼容）
- 如果你回复慢，可以在仓库 Variables 里加 `TG_LOGIN_TIMEOUT=600`（单位秒）
- 日志默认已开启（验证码会明文打印；`/pwd` 会自动隐藏密码）。如需关闭，设 `TG_DEBUG_UPDATES=0`
- 实在匹配不上，可临时加 `TG_ACCEPT_ANY=1`（不校验聊天 ID，只要收到 5~8 位数字验证码就用；跑通后请关闭）

## 5) 自动签到

工作流：`AUTO_SIGN`
- 支持 `workflow_dispatch` 手动运行
- 也包含 `schedule` 定时运行（注意 GitHub cron 是 **UTC**）

可选变量：
- `SIGN_DELAY_RANGE`：每条消息之间随机等待（默认 `1-3` 秒），例如 `0.5-2`



## 效果图

<img src="png/image11.png" alt="效果" width="300">
