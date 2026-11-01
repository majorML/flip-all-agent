#!/usr/bin/env python3
"""
Major — Discord bot layer
=========================
Connects Major's audit engine directly to Discord using discord.py.
This runs alongside agent.py (Switch protocol server) or standalone.

Usage:
    python discord_bot.py

Required env vars (from .env):
    DISCORD_TOKEN — your bot token
"""

from __future__ import annotations

import os
import sys
import asyncio
import textwrap
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

TOKEN = os.environ.get("DISCORD_TOKEN", "")
if not TOKEN:
    sys.exit("[error] DISCORD_TOKEN not set in .env")

try:
    import discord
except ImportError:
    sys.exit("[error] discord.py not installed — run: pip install discord.py")

# Import Major's core engine
from agent import handle_message, DID, SIGNING_KEY

DISCORD_CHAR_LIMIT = 1900  # leave headroom for formatting


def split_long(text: str, limit: int = DISCORD_CHAR_LIMIT) -> list[str]:
    """Split a long message into ≤limit-char chunks at newline boundaries."""
    if len(text) <= limit:
        return [text]
    chunks, current = [], ""
    for line in text.split("\n"):
        if len(current) + len(line) + 1 > limit:
            if current:
                chunks.append(current.rstrip())
            current = line + "\n"
        else:
            current += line + "\n"
    if current.strip():
        chunks.append(current.rstrip())
    return chunks or [text[:limit]]


class MajorClient(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)

    async def on_ready(self):
        sign_status = "✅ signing active" if SIGNING_KEY else "⚠️ signing inactive"
        print(f"[major] Logged in as {self.user} (ID: {self.user.id})")
        print(f"[major] DID: {DID}")
        print(f"[major] {sign_status}")
        print(f"[major] Listening for @Major mentions...")

    async def on_message(self, message: discord.Message):
        # Ignore own messages
        if message.author == self.user:
            return

        # Only respond when mentioned or when in DM
        is_mentioned = self.user in message.mentions
        is_dm = isinstance(message.channel, discord.DMChannel)

        if not (is_mentioned or is_dm):
            return

        content = message.content.strip()

        # Build the Switch-protocol body our engine expects
        body = {
            "content": content,
            "sender": {
                "name": str(message.author.display_name),
                "id": str(message.author.id),
            },
        }

        # Show typing indicator while Major "thinks"
        async with message.channel.typing():
            # Collect all SSE chunks from handle_message generator (sync)
            loop = asyncio.get_event_loop()
            full_text = await loop.run_in_executor(None, self._collect_response, body)

        # Send in chunks if needed (Discord 2000-char limit)
        chunks = split_long(full_text)
        for i, chunk in enumerate(chunks):
            if i == 0:
                await message.reply(chunk, mention_author=False)
            else:
                await message.channel.send(chunk)

    def _collect_response(self, body: dict) -> str:
        """Run the sync generator and collect all text."""
        import json
        parts = []
        for chunk in handle_message(body):
            raw = chunk.decode("utf-8", errors="replace")
            for line in raw.split("\n"):
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[5:].strip())
                        if data.get("content"):
                            parts.append(data["content"])
                    except (json.JSONDecodeError, KeyError):
                        pass
        return " ".join(parts)


def main():
    client = MajorClient()
    print(f"[major] Starting Discord bot...")
    client.run(TOKEN, log_handler=None)


if __name__ == "__main__":
    main()
