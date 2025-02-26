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
import re
import aiohttp
from urllib.parse import urlparse
import asyncio
from datetime import timedelta

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

    async def analyze_message(self, content: str) -> Dict[str, any]:
        """Analyze message content using OpenAI API"""
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Du bist ein Moderations-Assistent. Analysiere den folgenden Text auf unangemessene Inhalte wie Beleidigungen, Hassrede, oder andere Verstöße. Antworte im JSON-Format mit den Feldern: is_inappropriate (bool), category (string), severity (float 0-1), reason (string)."},
                    {"role": "user", "content": content}
                ],
                temperature=0
            )
            
            result = response.choices[0].message.content
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse OpenAI response: {result}")
                return {"is_inappropriate": False, "category": None, "severity": 0, "reason": "Analysis failed"}
                
        except Exception as e:
            logger.error(f"Error analyzing message with OpenAI: {e}")
            return {"is_inappropriate": False, "category": None, "severity": 0, "reason": "Analysis failed"}

    async def is_valid_url(self, url: str) -> bool:
        """Check if a URL is syntactically valid"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    async def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from a text"""
        # More comprehensive URL pattern that includes paths and query parameters
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^"\s<>]*)?'
        urls = re.findall(url_pattern, text)
        logger.info(f"Found URLs in message: {urls}")
        return urls

    async def is_known_malware_test(self, url: str) -> bool:
        """Check if URL points to known malware test files"""
        known_patterns = [
            r'eicar\.com',
            r'test-virus',
            r'malware-test',
            r'virus-test'
        ]
        return any(re.search(pattern, url.lower()) for pattern in known_patterns)

    async def check_url_safety(self, url: str) -> Dict[str, any]:
        """Check URL safety using urlscan.io"""
        logger.info(f"Starting safety check for URL: {url}")
        
        # First check for known malware test files
        logger.info("Checking for known malware patterns...")
        if await self.is_known_malware_test(url):
            logger.warning(f"URL contains known malware test pattern: {url}")
            return {
                'safe': False,
                'reason': "URL points to known malware test file",
                'score': 100
            }
        
        logger.info("No known malware patterns found, proceeding with urlscan.io check...")
        api_key = os.getenv('URLSCAN_API_KEY')
        if not api_key:
            logger.error("URLSCAN_API_KEY not found in environment variables")
            return {'safe': True, 'reason': 'URL scan skipped - No API key'}

        logger.info("Using URLSCAN_API_KEY: " + api_key[:8] + "...")  # Log only first 8 chars for security

        headers = {
            'API-Key': api_key,
            'Content-Type': 'application/json',
        }
        data = {
            'url': url,
            'visibility': 'public'
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                # Submit scan
                logger.info("Submitting URL scan...")
                async with session.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data) as response:
                    response_text = await response.text()
                    logger.info(f"Scan submission response status: {response.status}")
                    logger.info(f"Scan submission response: {response_text}")
                    
                    if response.status != 200:
                        logger.error(f"Failed to submit URL scan: {response_text}")
                        return {'safe': False, 'reason': 'Failed to scan URL'}
                    
                    scan_data = await response.json()
                    scan_uuid = scan_data['uuid']
                    logger.info(f"Scan UUID: {scan_uuid}")
                    
                    # Wait for scan to complete with timeout
                    max_retries = 10
                    retry_delay = 3
                    
                    for attempt in range(max_retries):
                        logger.info(f"Waiting for scan results (attempt {attempt + 1}/{max_retries})...")
                        await asyncio.sleep(retry_delay)
                        
                        result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
                        async with session.get(result_url) as result_response:
                            if result_response.status == 200:
                                result = await result_response.json()
                                logger.info("Received scan results")
                                logger.info(f"Full scan results: {json.dumps(result, indent=2)}")
                                
                                # Check for malicious indicators
                                verdicts = result.get('verdicts', {})
                                overall = verdicts.get('overall', {})
                                
                                # Get detailed threat data
                                page = result.get('page', {})
                                status = page.get('status')
                                if status in [403, 404, 500]:
                                    logger.warning(f"URL returned error status: {status}")
                                    return {
                                        'safe': False,
                                        'reason': f"URL returned error status {status}",
                                        'score': overall.get('score', 0)
                                    }

                                # Check file downloads
                                requests = result.get('data', {}).get('requests', [])
                                for request in requests:
                                    response = request.get('response', {})
                                    if response.get('mimeType', '').startswith(('application/', 'binary/')):
                                        logger.warning(f"URL attempts to download files: {response.get('mimeType')}")
                                        return {
                                            'safe': False,
                                            'reason': f"URL attempts to download files of type: {response.get('mimeType')}",
                                            'score': overall.get('score', 0)
                                        }
                                
                                if overall.get('malicious'):
                                    logger.warning(f"URL flagged as malicious: {url}")
                                    return {
                                        'safe': False,
                                        'reason': f"URL flagged as malicious (Score: {overall.get('score', 0)})",
                                        'score': overall.get('score', 0),
                                        'categories': overall.get('categories', [])
                                    }
                                
                                # Check for specific threats
                                threats = result.get('threats', [])
                                if threats:
                                    logger.warning(f"URL contains threats: {url}")
                                    return {
                                        'safe': False,
                                        'reason': f"URL contains threats: {', '.join(t.get('id', 'unknown') for t in threats)}",
                                        'threats': threats
                                    }

                                # Additional security checks
                                lists = verdicts.get('urlscan', {}).get('lists', [])
                                if any(item in lists for item in ['malicious', 'phishing', 'suspicious']):
                                    logger.warning(f"URL found in malicious lists: {lists}")
                                    return {
                                        'safe': False,
                                        'reason': f"URL found in malicious lists: {', '.join(lists)}",
                                        'lists': lists
                                    }
                                
                                logger.info(f"URL appears safe: {url}")
                                return {
                                    'safe': True,
                                    'score': overall.get('score', 0)
                                }
                            else:
                                logger.warning(f"Failed to get scan results (attempt {attempt + 1}): {await result_response.text()}")
                    
                    logger.error("Scan timeout - results not available")
                    return {'safe': False, 'reason': 'Scan timeout - results not available'}
                    
            except Exception as e:
                logger.error(f"Error checking URL safety: {str(e)}")
                return {'safe': False, 'reason': f'Error checking URL: {str(e)}'}

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

    async def on_message(self, message):
        """Handle incoming messages"""
        if message.author == self.user:
            return

        try:
            # Log incoming message
            logger.info(f"Processing message from {message.author.name}: {message.content}")
            
            # Extract URLs from message
            urls = await self.extract_urls(message.content)
            if urls:
                logger.info(f"Found {len(urls)} URLs in message")
                for url in urls:
                    try:
                        # Check URL safety
                        safety_result = await self.check_url_safety(url)
                        logger.info(f"Safety check result for {url}: {safety_result}")
                        
                        if not safety_result['safe']:
                            # Delete unsafe message
                            try:
                                await message.delete()
                                logger.info(f"Deleted message with unsafe URL: {url}")
                            except discord.errors.NotFound:
                                logger.warning("Message already deleted or not found")
                            except Exception as e:
                                logger.error(f"Error deleting message: {str(e)}")
                            
                            # Issue warning
                            warning_msg = f"⚠️ {message.author.mention} Warning: The URL you posted was flagged as unsafe.\nReason: {safety_result.get('reason', 'Unknown')}"
                            await message.channel.send(warning_msg, delete_after=10)
                            
                            # Record warning
                            await self.add_warning(
                                message.author.id,
                                message.guild.id if message.guild else None,
                                1,  # Warning level
                                safety_result.get('reason', 'Posted unsafe URL'),
                                message.content
                            )
                    except Exception as e:
                        logger.error(f"Error processing URL {url}: {str(e)}")
            
            # Process message content with AI
            await self.process_message_content(message)
            
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}", exc_info=True)

    async def process_message_content(self, message):
        """Process message content with AI"""
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

    async def handle_violation(self, message: discord.Message, level: str, reason: str):
        """Handle a message that violates the rules"""
        try:
            # Nachricht löschen
            await message.delete()
            
            # Warnung in der Datenbank speichern
            await self.add_warning(message.author.id, message.guild.id, level, reason, message.content)
            
            # Warnung im Chat senden
            warning_message = f"⚠️ Warnung für {message.author.mention}!\nGrund: {reason}"
            
            # Timeout für schwere Verstöße
            if level == 'severe':
                duration = timedelta(seconds=self.config['timeout_duration'])
                try:
                    await message.author.timeout_for(duration, reason=reason)
                    warning_message += f"\n🕒 Timeout für {self.config['timeout_duration']} Sekunden"
                except discord.errors.Forbidden:
                    warning_message += "\n⚠️ Konnte keinen Timeout verhängen (fehlende Berechtigungen)"
            
            # Warnung im Chat und Log-Channel senden
            warning = await message.channel.send(warning_message)
            
            # Nach 10 Sekunden die Warnung löschen (optional)
            await asyncio.sleep(10)
            try:
                await warning.delete()
            except discord.errors.NotFound:
                pass  # Warnung wurde bereits gelöscht
            
            # In Log-Channel protokollieren
            if self.config.get('log_channel_name'):
                log_channel = discord.utils.get(message.guild.channels, name=self.config['log_channel_name'])
                if log_channel:
                    embed = discord.Embed(
                        title="Moderation: Nachricht entfernt",
                        description=f"**Benutzer:** {message.author.mention}\n"
                                  f"**Kanal:** {message.channel.mention}\n"
                                  f"**Grund:** {reason}\n"
                                  f"**Level:** {level}\n"
                                  f"**Originalnachricht:** {message.content}",
                        color=discord.Color.red(),
                        timestamp=datetime.utcnow()
                    )
                    await log_channel.send(embed=embed)
                    
        except Exception as e:
            logger.error(f"Error handling violation: {e}")

    @commands.command(name='report')
    async def report_message(self, ctx, message_id: int, *, reason: str = None):
        """Meldet eine Nachricht zur Überprüfung"""
        try:
            message = await ctx.channel.fetch_message(message_id)
            analysis = await self.analyze_message(message.content)
            
            if analysis['is_inappropriate'] or reason:
                await self.handle_violation(message, 'mild', reason or analysis['reason'])
                await ctx.send(f'✅ Nachricht wurde gemeldet und überprüft.')
            else:
                await ctx.send('❌ Die Nachricht enthält keine erkennbaren Verstöße.')
        except Exception as e:
            await ctx.send('❌ Fehler beim Melden der Nachricht. Überprüfe die Nachrichten-ID.')
            logger.error(f"Error reporting message: {e}")

    @commands.command(name='warnings')
    async def show_warnings(self, ctx, member: discord.Member = None):
        """Zeigt die Verwarnungen eines Benutzers an"""
        target = member or ctx.author
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                'SELECT * FROM warnings WHERE user_id = ? AND guild_id = ? ORDER BY timestamp DESC',
                (target.id, ctx.guild.id)
            ) as cursor:
                warnings = await cursor.fetchall()
        
        if not warnings:
            await ctx.send(f'✅ {target.mention} hat keine Verwarnungen.')
            return
            
        embed = discord.Embed(
            title=f"Verwarnungen für {target.name}",
            color=discord.Color.orange()
        )
        
        for warning in warnings:
            embed.add_field(
                name=f"{warning['warning_level']} - {warning['timestamp']}",
                value=warning['reason'],
                inline=False
            )
            
        await ctx.send(embed=embed)

    @commands.command(name='clearwarnings')
    @commands.has_permissions(administrator=True)
    async def clear_warnings(self, ctx, member: discord.Member):
        """Löscht alle Verwarnungen eines Benutzers (nur für Administratoren)"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                'DELETE FROM warnings WHERE user_id = ? AND guild_id = ?',
                (member.id, ctx.guild.id)
            )
            await db.commit()
            
        await ctx.send(f'✅ Alle Verwarnungen von {member.mention} wurden gelöscht.')

    @commands.command(name='help')
    async def show_help(self, ctx):
        """Zeigt die Hilfe für alle Befehle an"""
        embed = discord.Embed(
            title="ModGuard Hilfe",
            description="Hier sind alle verfügbaren Befehle:",
            color=discord.Color.blue()
        )
        
        commands_info = {
            "report": "!report <message_id> [grund] - Meldet eine Nachricht zur Überprüfung",
            "warnings": "!warnings [@user] - Zeigt die Verwarnungen eines Benutzers an",
            "clearwarnings": "!clearwarnings @user - Löscht alle Verwarnungen eines Benutzers (nur Admin)",
            "help": "!help - Zeigt diese Hilfe an"
        }
        
        for cmd, desc in commands_info.items():
            embed.add_field(name=cmd, value=desc, inline=False)
            
        await ctx.send(embed=embed)

if __name__ == '__main__':
    bot = ModGuard()
    bot.run(os.getenv('DISCORD_TOKEN'))
