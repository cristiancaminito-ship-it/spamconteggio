from __future__ import annotations

import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    MessageEntity,
    Update,
)
from telegram.constants import ChatType
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

LOGGER = logging.getLogger("telegram_spam_bot")
LINK_PATTERN = re.compile(
    r"(?:https?://|www\.|t\.me/|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)",
    re.IGNORECASE,
)
LINK_ENTITY_TYPES = {MessageEntity.URL, MessageEntity.TEXT_LINK}
HISTORY_RETENTION_DAYS = 45


class SecretRedactionFilter(logging.Filter):
    """Redact the bot token from third-party library and application logs."""

    def __init__(self, secret: str) -> None:
        super().__init__()
        self.secret = secret

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secret:
            rendered = record.getMessage()
            if self.secret in rendered:
                record.msg = rendered.replace(self.secret, "[REDACTED]")
                record.args = ()
        return True


@dataclass(frozen=True)
class BotConfig:
    token: str
    daily_limit: int
    timezone_name: str
    database_path: str

    @property
    def timezone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone_name)

    @classmethod
    def from_environment(cls) -> BotConfig:
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError(
                "TELEGRAM_BOT_TOKEN is missing. Add your BotFather token "
                "to Replit Secrets."
            )

        raw_limit = os.getenv("DAILY_SPAM_LIMIT", "1")
        try:
            daily_limit = int(raw_limit)
        except ValueError as exc:
            raise RuntimeError("DAILY_SPAM_LIMIT must be a whole number.") from exc
        if daily_limit < 0:
            raise RuntimeError("DAILY_SPAM_LIMIT cannot be negative.")

        timezone_name = os.getenv("BOT_TIMEZONE", "Europe/Rome").strip()
        try:
            ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise RuntimeError(
                f"BOT_TIMEZONE is not a recognized timezone: {timezone_name!r}."
            ) from exc

        return cls(
            token=token,
            daily_limit=daily_limit,
            timezone_name=timezone_name,
            database_path=os.getenv("SPAM_DB_PATH", "telegram_spam.sqlite3"),
        )


@dataclass(frozen=True)
class UsageDecision:
    count: int
    allowed: bool


def _has_link_entity(entities: list[MessageEntity] | None) -> bool:
    return any(entity.type in LINK_ENTITY_TYPES for entity in entities or [])


def message_is_spam(message: Message) -> bool:
    """Return true for photo messages or messages with a visible/hidden URL."""
    if message.photo:
        return True

    if _has_link_entity(message.entities) or _has_link_entity(message.caption_entities):
        return True

    text = message.text or ""
    caption = message.caption or ""
    return bool(LINK_PATTERN.search(text) or LINK_PATTERN.search(caption))


class UsageStore:
    """Persist per-chat, per-member daily spam counts."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        self._connection: sqlite3.Connection | None = None

    def initialize(self) -> None:
        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=30,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_usage (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                local_day TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (chat_id, user_id, local_day)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS known_groups (
                chat_id INTEGER PRIMARY KEY,
                title TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS group_limits (
                chat_id INTEGER PRIMARY KEY,
                daily_limit INTEGER NOT NULL CHECK (daily_limit >= 0)
            )
            """
        )

    def register_group(self, chat_id: int, title: str) -> None:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        self._connection.execute(
            """
            INSERT INTO known_groups (chat_id, title) VALUES (?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET title = excluded.title
            """,
            (chat_id, title),
        )

    def list_groups(self) -> list[tuple[int, str]]:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        rows = self._connection.execute(
            "SELECT chat_id, title FROM known_groups ORDER BY title COLLATE NOCASE"
        ).fetchall()
        return [(int(chat_id), str(title)) for chat_id, title in rows]

    def get_group_title(self, chat_id: int) -> str | None:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        row = self._connection.execute(
            "SELECT title FROM known_groups WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
        return str(row[0]) if row else None

    def get_daily_limit(self, chat_id: int, default: int) -> int:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        row = self._connection.execute(
            "SELECT daily_limit FROM group_limits WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
        return int(row[0]) if row else default

    def set_daily_limit(self, chat_id: int, daily_limit: int) -> None:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        if daily_limit < 0:
            raise ValueError("daily_limit cannot be negative.")
        self._connection.execute(
            """
            INSERT INTO group_limits (chat_id, daily_limit) VALUES (?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET daily_limit = excluded.daily_limit
            """,
            (chat_id, daily_limit),
        )

    def record_spam(
        self,
        chat_id: int,
        user_id: int,
        local_day: date,
        daily_limit: int,
    ) -> UsageDecision:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        day_key = local_day.isoformat()
        cutoff = (local_day - timedelta(days=HISTORY_RETENTION_DAYS)).isoformat()
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("DELETE FROM daily_usage WHERE local_day < ?", (cutoff,))
            row = connection.execute(
                """
                SELECT count FROM daily_usage
                WHERE chat_id = ? AND user_id = ? AND local_day = ?
                """,
                (chat_id, user_id, day_key),
            ).fetchone()

            if row is None:
                count = 1
                connection.execute(
                    """
                    INSERT INTO daily_usage (chat_id, user_id, local_day, count)
                    VALUES (?, ?, ?, ?)
                    """,
                    (chat_id, user_id, day_key, count),
                )
            else:
                count = int(row[0]) + 1

            allowed = count <= daily_limit
            connection.execute(
                """
                UPDATE daily_usage SET count = ?
                WHERE chat_id = ? AND user_id = ? AND local_day = ?
                """,
                (count, chat_id, user_id, day_key),
            )
            connection.execute("COMMIT")
            return UsageDecision(count=count, allowed=allowed)
        except Exception:
            connection.execute("ROLLBACK")
            raise

    def get_count(self, chat_id: int, user_id: int, local_day: date) -> int:
        if self._connection is None:
            raise RuntimeError("UsageStore.initialize() must be called first.")
        row = self._connection.execute(
            """
            SELECT count FROM daily_usage
            WHERE chat_id = ? AND user_id = ? AND local_day = ?
            """,
            (chat_id, user_id, local_day.isoformat()),
        ).fetchone()
        return int(row[0]) if row else 0

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None


async def start_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    del context
    if (
        update.effective_chat is None
        or update.effective_chat.type != ChatType.PRIVATE
        or update.effective_message is None
    ):
        return
    await update.effective_message.reply_text(
        "I help moderate group spam. I count messages containing a link or photo "
        "per member and delete matching messages after the daily allowance is used. "
        "Group administrators are exempt. To choose a group's allowance, run "
        "/limit in that group and then run /limit here in private."
    )


async def help_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    await start_command(update, context)


async def _is_group_admin(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    user_id: int,
) -> bool:
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
    except TelegramError as exc:
        LOGGER.warning(
            "Could not verify a user's group role for limit settings (%s).",
            type(exc).__name__,
        )
        return False
    return member.status in ("creator", "administrator")


async def limit_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if message is None or chat is None:
        return

    store: UsageStore = context.application.bot_data["usage_store"]
    if chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
        store.register_group(
            chat.id,
            getattr(chat, "title", None) or f"Group {chat.id}",
        )
        return
    if chat.type != ChatType.PRIVATE or user is None:
        return

    config: BotConfig = context.application.bot_data["config"]
    available_groups: list[tuple[int, str]] = []
    for chat_id, title in store.list_groups():
        if await _is_group_admin(context, chat_id, user.id):
            available_groups.append((chat_id, title))

    if not available_groups:
        await message.reply_text(
            "No groups are available for limit settings yet. Start this bot in "
            "private, then run /limit once in each group you manage. That command "
            "does not post a message in the group. Then run /limit here."
        )
        return

    keyboard = [
        [
            InlineKeyboardButton(
                title[:64],
                callback_data=f"limit:group:{chat_id}",
            )
        ]
        for chat_id, title in available_groups
    ]
    await message.reply_text(
        "Choose a group to set its daily allowance. The current default is "
        f"{config.daily_limit} link/photo message(s) per member.",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def limit_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()

    message = query.message
    if message is None or message.chat.type != ChatType.PRIVATE:
        return

    parts = (query.data or "").split(":")
    if len(parts) not in (3, 4) or parts[0] != "limit":
        return
    action = parts[1]
    try:
        chat_id = int(parts[2])
    except ValueError:
        return

    if not await _is_group_admin(context, chat_id, query.from_user.id):
        await query.edit_message_text(
            "I could not verify that you are an administrator of this group. "
            "Run /limit again if your permissions have changed."
        )
        return

    store: UsageStore = context.application.bot_data["usage_store"]
    config: BotConfig = context.application.bot_data["config"]
    title = store.get_group_title(chat_id)
    if title is None:
        await query.edit_message_text(
            "That group is no longer registered. Run /limit in the group, "
            "then try again here."
        )
        return

    if action == "group" and len(parts) == 3:
        current_limit = store.get_daily_limit(chat_id, config.daily_limit)
        values = (0, 1, 2, 3, 5, 10)
        buttons = [
            InlineKeyboardButton(
                f"{value}{' ✓' if value == current_limit else ''}",
                callback_data=f"limit:set:{chat_id}:{value}",
            )
            for value in values
        ]
        keyboard = [buttons[:3], buttons[3:]]
        keyboard.append(
            [
                InlineKeyboardButton(
                    "Enter another number",
                    callback_data=f"limit:custom:{chat_id}",
                )
            ]
        )
        await query.edit_message_text(
            f"{title}\n\nChoose how many link/photo messages each member may "
            "send per day. Choose 0 to delete every matching message.",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )
        return

    if action == "custom" and len(parts) == 3:
        context.user_data["pending_limit_chat_id"] = chat_id
        await query.edit_message_text(
            f"Send a whole number from 0 to 1000 for {title}'s daily allowance."
        )
        return

    if action == "set" and len(parts) == 4:
        try:
            daily_limit = int(parts[3])
        except ValueError:
            return
        if not 0 <= daily_limit <= 1000:
            return
        store.set_daily_limit(chat_id, daily_limit)
        await query.edit_message_text(
            f"{title}: the daily allowance is now {daily_limit} "
            "link/photo message(s) per member."
        )


async def custom_limit_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    message = update.effective_message
    user = update.effective_user
    if (
        message is None
        or update.effective_chat is None
        or update.effective_chat.type != ChatType.PRIVATE
        or user is None
    ):
        return

    chat_id = context.user_data.get("pending_limit_chat_id")
    if not isinstance(chat_id, int):
        return

    try:
        daily_limit = int(message.text or "")
    except ValueError:
        await message.reply_text("Enter a whole number from 0 to 1000.")
        return
    if not 0 <= daily_limit <= 1000:
        await message.reply_text("Enter a whole number from 0 to 1000.")
        return

    if not await _is_group_admin(context, chat_id, user.id):
        context.user_data.pop("pending_limit_chat_id", None)
        await message.reply_text(
            "I could not verify that you are an administrator of that group."
        )
        return

    store: UsageStore = context.application.bot_data["usage_store"]
    title = store.get_group_title(chat_id)
    if title is None:
        context.user_data.pop("pending_limit_chat_id", None)
        await message.reply_text(
            "That group is no longer registered. Run /limit in the group "
            "and try again."
        )
        return

    store.set_daily_limit(chat_id, daily_limit)
    context.user_data.pop("pending_limit_chat_id", None)
    await message.reply_text(
        f"{title}: the daily allowance is now {daily_limit} "
        "link/photo message(s) per member."
    )


async def moderate_group_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if (
        message is None
        or chat is None
        or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP)
    ):
        return

    application = context.application
    store: UsageStore = application.bot_data["usage_store"]
    config: BotConfig = application.bot_data["config"]
    store.register_group(
        chat.id,
        getattr(chat, "title", None) or f"Group {chat.id}",
    )
    if user is None or not message_is_spam(message):
        return

    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
    except TelegramError as exc:
        LOGGER.warning(
            "Could not verify a sender's group role; skipped moderation (%s).",
            type(exc).__name__,
        )
        return

    if member.status in ("creator", "administrator"):
        return

    local_day = datetime.now(config.timezone).date()
    daily_limit = store.get_daily_limit(chat.id, config.daily_limit)
    decision = store.record_spam(chat.id, user.id, local_day, daily_limit)
    if decision.allowed:
        return

    try:
        await message.delete()
    except TelegramError as exc:
        LOGGER.error(
            "Could not delete an over-limit message (%s); check bot admin permissions.",
            type(exc).__name__,
        )


def build_application(config: BotConfig, store: UsageStore) -> Application:
    application = Application.builder().token(config.token).build()
    application.bot_data["config"] = config
    application.bot_data["usage_store"] = store
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("limit", limit_command))
    application.add_handler(CallbackQueryHandler(limit_callback, pattern=r"^limit:"))
    application.add_handler(
        MessageHandler(
            filters.ChatType.PRIVATE & filters.TEXT & ~filters.COMMAND,
            custom_limit_message,
        )
    )
    application.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS & ~filters.COMMAND,
            moderate_group_message,
        )
    )
    return application


def main() -> None:
    config = BotConfig.from_environment()
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    redaction_filter = SecretRedactionFilter(config.token)
    for handler in logging.getLogger().handlers:
        handler.addFilter(redaction_filter)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    store = UsageStore(config.database_path)
    store.initialize()
    application = build_application(config, store)

    LOGGER.info(
        "Starting group moderation: daily limit=%d, timezone=%s.",
        config.daily_limit,
        config.timezone_name,
    )
    try:
        application.run_polling(
            allowed_updates=[Update.MESSAGE, Update.CALLBACK_QUERY],
            drop_pending_updates=True,
        )
    finally:
        store.close()


if __name__ == "__main__":
    main()
