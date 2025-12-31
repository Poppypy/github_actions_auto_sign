import asyncio
from datetime import datetime, timedelta, timezone
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError, FloodWaitError
from telethon.errors.rpcerrorlist import PhoneCodeInvalidError, PasswordHashInvalidError
from telethon.tl.functions.messages import SendMessageRequest
import random
# 条100是极限
# Replace these with your own values
API_ID = 31050687  # Your API ID from my.telegram.org
API_HASH = '9b6a52e716316a59b21ade09c59a73cd'  # Your API Hash from my.telegram.org
PHONE_NUMBER = '+8619196080947'  # Your phone number in international format
# BOT_USERNAME ='@Carll_Bomb_bot'
# BOT_USERNAME ='@jdHappybot'  # Or use the user ID: 5969411283


# BOT_USERNAME ='@WS_NCBOT'  # 开户
# BOT_USERNAME ='@AEON_SGKBOT'  # 开户
# BOT_USERNAME ='@jrsgk4_bot'  # 开户巨人社工库
# BOT_USERNAME ='@GnoranceX_bot'  # 开户
BOT_USERNAME ='@xiaohaige_baiyubot'  # 开户一诺

# MESSAGE_TEXT = '/hz 15574978289 5'  # The message to send


MESSAGE_TEXT = '/qd'  # The message to send



# =======================固定=======================================
START_DATE = datetime(2025, 12, 16, tzinfo=timezone(timedelta(hours=8)))
END_DATE   = datetime(2026, 3, 16, tzinfo=timezone(timedelta(hours=8)))


SCHEDULE_HOUR = 12
SCHEDULE_MINUTE = 18


# async def login_and_authenticate(client):
#     await client.connect()
#     if await client.is_user_authorized():
#         print("Already logged in.")
#         return
#
#     print("Sending code request...")
#     sent_code = await client.send_code_request(PHONE_NUMBER)
#
#     while True:
#         code = input("Enter the login code you received: ")
#         try:
#             await client.sign_in(PHONE_NUMBER, code, phone_code_hash=sent_code.phone_code_hash)
#             print("Login successful!")
#             break
#         except PhoneCodeInvalidError:
#             print("Invalid code. Please try again.")
#         except SessionPasswordNeededError:
#             await handle_2fa(client)
#             break
#         except Exception as e:
#             print(f"Unexpected error during sign_in: {e}")
#
#
# async def handle_2fa(client):
#     while True:
#         password = input("Two-step verification is enabled. Enter your password: ")
#         try:
#             await client.sign_in(password=password)
#             print("2FA successful!")
#             break
#         except PasswordHashInvalidError:
#             print("Invalid password. Please try again.")
#         except Exception as e:
#             print(f"Unexpected error during 2FA: {e}")
#
#
# async def main():
#     client = TelegramClient('telegram_session', API_ID, API_HASH, connection_retries=None)
#     await login_and_authenticate(client)
#
#     try:
#         peer = await client.get_input_entity(BOT_USERNAME)
#     except Exception as e:
#         print(f"Error getting peer: {e}")
#         await client.disconnect()
#         return
#
#     current_date = START_DATE
#
#     while current_date <= END_DATE:
#         # Fixed time 12:18
#         schedule_datetime = current_date.replace(
#             hour=SCHEDULE_HOUR,
#             minute=SCHEDULE_MINUTE,
#             second=0,
#             microsecond=0
#         )
#
#         now_utc = datetime.now(timezone.utc)
#         if schedule_datetime <= now_utc:
#             print(f"Skipping past or current time: {schedule_datetime}")
#             current_date += timedelta(days=1)
#             continue
#
#         schedule_unix = int(schedule_datetime.timestamp())
#
#         while True:
#             try:
#                 print(f"Scheduling message for {schedule_datetime}")
#                 await client(SendMessageRequest(
#                     peer=peer,
#                     message=MESSAGE_TEXT,
#                     schedule_date=schedule_unix
#                 ))
#                 break
#             except FloodWaitError as e:
#                 print(f"Flood wait for {e.seconds} seconds...")
#                 await asyncio.sleep(e.seconds)
#             except Exception as e:
#                 print(f"Error scheduling message: {e}")
#                 break
#
#         current_date += timedelta(days=1)
#
#     print("All messages scheduled successfully!")
#     await client.disconnect()
#
# asyncio.run(main())
#








# ==========随机=============


async def login_and_authenticate(client):
    await client.connect()
    if await client.is_user_authorized():
        print("Already logged in.")
        return

    print("Sending code request...")
    sent_code = await client.send_code_request(PHONE_NUMBER)

    while True:
        code = input("Enter the login code you received: ")
        try:
            await client.sign_in(PHONE_NUMBER, code, phone_code_hash=sent_code.phone_code_hash)
            print("Login successful!")
            break
        except PhoneCodeInvalidError:
            print("Invalid code. Please try again.")
        except SessionPasswordNeededError:
            await handle_2fa(client)
            break
        except Exception as e:
            print(f"Unexpected error during sign_in: {e}")


async def handle_2fa(client):
    while True:
        password = input("Two-step verification is enabled. Enter your password: ")
        try:
            await client.sign_in(password=password)
            print("2FA successful!")
            break
        except PasswordHashInvalidError:
            print("Invalid password. Please try again.")
        except Exception as e:
            print(f"Unexpected error during 2FA: {e}")


async def main():
    client = TelegramClient('telegram_session', API_ID, API_HASH, connection_retries=None)
    await login_and_authenticate(client)

    try:
        peer = await client.get_input_entity(BOT_USERNAME)
    except Exception as e:
        print(f"Error getting peer: {e}")
        await client.disconnect()
        return

    current_date = START_DATE

    while current_date <= END_DATE:
        # Random time between 12:00 and 18:00
        random_hour = random.randint(12, 18)
        random_minute = random.randint(0, 59)

        schedule_datetime = current_date.replace(
            hour=random_hour,
            minute=random_minute,
            second=0,
            microsecond=0
        )

        now_utc = datetime.now(timezone.utc)
        if schedule_datetime <= now_utc:
            print(f"Skipping past or current time: {schedule_datetime}")
            current_date += timedelta(days=1)
            continue

        schedule_unix = int(schedule_datetime.timestamp())

        while True:
            try:
                print(f"Scheduling message for {schedule_datetime}")
                await client(SendMessageRequest(
                    peer=peer,
                    message=MESSAGE_TEXT,
                    schedule_date=schedule_unix
                ))
                break
            except FloodWaitError as e:
                print(f"Flood wait for {e.seconds} seconds...")
                await asyncio.sleep(e.seconds)
            except Exception as e:
                print(f"Error scheduling message: {e}")
                break

        current_date += timedelta(days=1)

    print("All messages scheduled successfully!")
    await client.disconnect()

asyncio.run(main())
