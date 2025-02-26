import discord
from discord.ext import commands
import openai
import json
import aiosqlite
import os
from dotenv import load_dotenv
import logging
from datetime import datetime
import requests
from typing import Optional, Dict, List

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('modguard')

class ModGuard(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        
        super().__init__(command_prefix='!', intents=intents)
        
        openai.api_key = os.getenv('OPENAI_API_KEY')
        self.db_path = 'modguard.db'
        self.config = self.load_config()
        
    async def setup_hook(self):
        await self.setup_database()
        
    def load_config(self) -> Dict:
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            default_config = {
                'warning_levels': {
                    'mild': {'action': 'warn', 'threshold': 0.7},
                    'moderate': {'action': 'timeout', 'threshold': 0.8},
                    'severe': {'action': 'ban', 'threshold': 0.9}
                },
                'timeout_duration': 3600,  # 1 hour
                'log_channel_name': 'mod-logs',
                'whitelist': [],
                'language': 'en'
            }
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=4)
            return default_config

    async def setup_database(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS warnings (
                    user_id INTEGER,
                    guild_id INTEGER,
                    warning_level TEXT,
                    reason TEXT,
                    timestamp DATETIME,
                    message_content TEXT
                )
            ''')
            await db.commit()

    async def analyze_message(self, message: str) -> Dict:
        try:
            response = openai.Completion.create(
                engine="davinci",
                prompt="You are a content moderator. Analyze the following message and determine if it contains inappropriate content. Respond with a JSON object containing 'is_inappropriate', 'category', 'severity' (0-1), and 'reason'.\n\n" + message,
                max_tokens=2048,
                temperature=0.5,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0
            )
            return json.loads(response.choices[0].text)
        except Exception as e:
            logger.error(f"Error analyzing message with OpenAI: {e}")
            return {"is_inappropriate": False, "category": None, "severity": 0, "reason": "Analysis failed"}

    async def check_link_safety(self, url: str) -> bool:
        # Implement link checking using Google Safe Browsing API
        api_key = os.getenv('SAFE_BROWSING_API_KEY')
        if not api_key:
            return True
        
        try:
            response = requests.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
                json={
                    'client': {'clientId': 'ModGuard', 'clientVersion': '1.0.0'},
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                }
            )
            return 'matches' not in response.json()
        except Exception as e:
            logger.error(f"Error checking link safety: {e}")
            return True

    async def add_warning(self, user_id: int, guild_id: int, level: str, reason: str, message_content: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                'INSERT INTO warnings (user_id, guild_id, warning_level, reason, timestamp, message_content) VALUES (?, ?, ?, ?, ?, ?)',
                (user_id, guild_id, level, reason, datetime.utcnow(), message_content)
            )
            await db.commit()

    async def get_warning_count(self, user_id: int, guild_id: int) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                'SELECT COUNT(*) FROM warnings WHERE user_id = ? AND guild_id = ?',
                (user_id, guild_id)
            ) as cursor:
                return (await cursor.fetchone())[0]

    async def on_ready(self):
        logger.info(f'ModGuard is online! Logged in as {self.user}')

    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return

        # Process commands first
        await self.process_commands(message)

        # Analyze message content
        analysis = await self.analyze_message(message.content)
        
        if analysis['is_inappropriate']:
            severity = analysis['severity']
            warning_level = None
            
            for level, config in self.config['warning_levels'].items():
                if severity >= config['threshold']:
                    warning_level = level
                    break
            
            if warning_level:
                await self.handle_violation(message, warning_level, analysis['reason'])

        # Check links in message
        for word in message.content.split():
            if word.startswith(('http://', 'https://')):
                if not await self.check_link_safety(word):
                    await self.handle_violation(message, 'moderate', 'Potentially unsafe link detected')

    async def handle_violation(self, message: discord.Message, level: str, reason: str):
        await self.add_warning(message.author.id, message.guild.id, level, reason, message.content)
        
        # Get log channel
        log_channel = discord.utils.get(message.guild.channels, name=self.config['log_channel_name'])
        if not log_channel:
            log_channel = await message.guild.create_text_channel(self.config['log_channel_name'])

        # Log the violation
        embed = discord.Embed(
            title="Moderation Action",
            color=discord.Color.red(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name="User", value=f"{message.author.mention} ({message.author.id})")
        embed.add_field(name="Level", value=level)
        embed.add_field(name="Reason", value=reason)
        embed.add_field(name="Message", value=message.content[:1024], inline=False)
        
        await log_channel.send(embed=embed)

        # Take action based on warning level
        action = self.config['warning_levels'][level]['action']
        if action == 'warn':
            await message.author.send(f"Warning: Your message was flagged for {reason}")
        elif action == 'timeout':
            duration = self.config['timeout_duration']
            await message.author.timeout(duration=duration)
        elif action == 'ban':
            await message.author.ban(reason=reason)

        # Delete the offending message
        await message.delete()

if __name__ == '__main__':
    bot = ModGuard()
    bot.run(os.getenv('DISCORD_TOKEN'))
