import discord
from discord.ext import commands
import openai
import json
import aiosqlite
import os
from dotenv import load_dotenv
import logging
from datetime import datetime, timedelta
import requests
from typing import Optional, Dict, List, Any
import re
import aiohttp
from urllib.parse import urlparse
import asyncio
from datetime import timezone

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
        intents.guilds = True
        intents.moderation = True
        intents.guild_messages = True
        
        super().__init__(command_prefix='!', intents=intents)
        
        openai.api_key = os.getenv('OPENAI_API_KEY')
        self.db_path = 'modguard.db'
        self.config = self.load_config()
        self.db = None
        
    async def setup_hook(self):
        """Setup hook that runs before the bot starts"""
        # Initialize database
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS warnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    guild_id INTEGER NOT NULL,
                    warning_level TEXT NOT NULL,
                    reason TEXT,
                    timestamp DATETIME NOT NULL,
                    message_content TEXT
                )
            ''')
            await db.commit()
        
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
                'language': 'en',
                'moderation': {
                    'auto_mod': {
                        'spam': {'action': 'timeout', 'duration': 30},
                        'hate_speech': {'action': 'ban'}
                    },
                    'warning_thresholds': {
                        'timeout': 3,
                        'kick': 5,
                        'ban': 7
                    },
                    'timeout_durations': {
                        'first': 30,
                        'second': 60,
                        'third': 120
                    }
                }
            }
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=4)
            return default_config

    async def analyze_message(self, content: str) -> Dict[str, Any]:
        """Analyze message content using OpenAI API"""
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": """
                    You are a moderation system for an English Discord server. Analyze the text for inappropriate content.
                    Respond in the following JSON format:
                    {
                        "is_inappropriate": true/false,
                        "violation_type": "mild"/"moderate"/"severe"/"none",
                        "reason": "Brief explanation"
                    }
                    
                    Violation types:
                    - mild: Mild insults, mild profanity
                    - moderate: Strong insults, discrimination
                    - severe: Hate speech, extreme harassment
                    - none: No violation
                    
                    Important: 
                    - Consider also English insults and profanity
                    - Recognize intentional misspellings (e.g. "wixxer" instead of "wichser")
                    - Check for hidden or implicit insults
                    """},
                    {"role": "user", "content": content}
                ]
            )
            
            result = json.loads(response.choices[0].message.content)
            logger.info(f"AI analysis result: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            return {
                "is_inappropriate": False,
                "violation_type": "none",
                "reason": "Error in analysis"
            }

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

    async def check_url_safety(self, url: str) -> Dict[str, Any]:
        """Check URL safety using urlscan.io"""
        logger.info(f"Starting safety check for URL: {url}")
        
        # First check for known malware patterns
        logger.info("Checking for known malware patterns...")
        if await self.is_known_malware_test(url):
            logger.warning(f"URL contains known malware test pattern: {url}")
            return {
                'safe': False,
                'reason': "URL points to known malware test file",
                'score': 100,
                'violation_type': 'unsafe_links'  # Add violation type for auto-mod
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

    async def add_warning(self, user_id: int, guild_id: int, level: str, reason: str = None, message_content: str = None):
        """Add a warning to the database"""
        # Format timestamp in ISO format for better compatibility
        timestamp = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO warnings (user_id, guild_id, warning_level, reason, timestamp, message_content) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, guild_id, level, reason, timestamp, message_content)
            )
            await db.commit()

    async def get_warning_count(self, user_id: int, guild_id: int) -> int:
        """Get warning count for a user"""
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
                            # Get violation type from safety result or use default
                            violation_type = safety_result.get('violation_type', 'unsafe_links')
                            await self.handle_violation(message, violation_type, safety_result['reason'])
                            break  # Stop checking other URLs after finding an unsafe one
                            
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
            violation_type = analysis['violation_type']
            await self.handle_violation(message, violation_type, analysis['reason'])

    async def handle_violation(self, message, violation_type: str, reason: str = None):
        """Handle a rule violation with automatic moderation"""
        try:
            # Log the violation
            user_id = message.author.id
            guild_id = message.guild.id
            
            # Delete the message
            try:
                await message.delete()
                logger.info(f"Deleted message with violation: {violation_type}")
            except Exception as e:
                logger.error(f"Failed to delete message: {str(e)}")

            # Find mod-logs channel
            mod_logs_channel = discord.utils.get(message.guild.channels, name='mod-logs')
            if not mod_logs_channel:
                logger.warning("No mod-logs channel found")
            
            # Send DM to user
            try:
                dm_embed = discord.Embed(
                    title="⚠️ Warning",
                    description=f"Your message has been removed.\nReason: {reason or violation_type}",
                    color=discord.Color.yellow()
                )
                await message.author.send(embed=dm_embed)
            except:
                logger.warning(f"Could not send DM to {message.author}")

            # Get auto-mod rules
            auto_mod_rules = self.config['moderation']['auto_mod']
            logger.info(f"Auto-mod rules: {auto_mod_rules}")
            logger.info(f"Processing violation type: {violation_type}")

            if violation_type in auto_mod_rules:
                rule = auto_mod_rules[violation_type]
                action = rule['action']
                
                if action == 'timeout':
                    duration = rule['duration']
                    until = datetime.now(timezone.utc) + timedelta(minutes=duration)
                    try:
                        # Debug info
                        logger.info(f"Bot permissions: {message.guild.me.guild_permissions}")
                        logger.info(f"Can bot moderate members: {message.guild.me.guild_permissions.moderate_members}")
                        logger.info(f"Bot roles: {[role.name for role in message.guild.me.roles]}")
                        logger.info(f"User roles: {[role.name for role in message.author.roles]}")
                        logger.info(f"Is user server owner: {message.author.id == message.guild.owner_id}")
                        
                        # Try to timeout the user
                        await message.author.timeout(until, reason=f"Auto-mod: {violation_type}")
                        logger.info(f"Applied timeout to {message.author} for {duration} minutes")
                        
                        # Send mod-log
                        if mod_logs_channel:
                            log_embed = discord.Embed(
                                title="🔨 Automatic Moderation",
                                description=f"**User:** {message.author.mention} ({message.author.id})\n"
                                            f"**Action:** Timeout for {duration} minutes\n"
                                            f"**Reason:** {violation_type.capitalize()} violation: {reason}",
                                color=0xFF9900
                            )
                            log_embed.add_field(name="Original Message", value=f"```{message.content[:500]}```")
                            log_embed.set_footer(text=f"Timeout expires: {until.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                            await mod_logs_channel.send(embed=log_embed)
                        
                        # DM the user
                        try:
                            user_embed = discord.Embed(
                                title="⚠️ Moderation Notice",
                                description=f"You have been timed out in **{message.guild.name}** for {duration} minutes.",
                                color=0xFF9900
                            )
                            user_embed.add_field(name="Reason", value=f"{violation_type.capitalize()} violation: {reason}")
                            user_embed.add_field(name="Your message", value=f"```{message.content[:500]}```")
                            user_embed.set_footer(text=f"Timeout expires: {until.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                            await message.author.send(embed=user_embed)
                        except Exception as e:
                            logger.error(f"Failed to DM user: {str(e)}")
                    
                    except discord.Forbidden:
                        logger.error(f"Failed to timeout user: Missing Permissions")
                    except Exception as e:
                        logger.error(f"Failed to timeout user: {str(e)}")
                    
                    # Add warning to database regardless of whether timeout succeeded
                    await self.add_warning(message.author.id, message.guild.id, violation_type, reason, message.content)
                
                elif action == 'kick':
                    try:
                        await message.author.kick(reason=f"Auto-mod: {violation_type}")
                        logger.info(f"Kicked user {message.author}")
                        
                        # Send mod-log
                        if mod_logs_channel:
                            log_embed = discord.Embed(
                                title="👢 Automatic Kick",
                                description=f"**User:** {message.author.mention}\n**Reason:** {violation_type}\n**Message:** {message.content}",
                                color=discord.Color.orange(),
                                timestamp=datetime.now(timezone.utc)
                            )
                            await mod_logs_channel.send(embed=log_embed)
                        
                    except Exception as e:
                        logger.error(f"Failed to kick user: {str(e)}")
                
                elif action == 'ban':
                    try:
                        await message.author.ban(reason=f"Auto-mod: {violation_type}")
                        logger.info(f"Banned user {message.author}")
                        
                        # Send mod-log
                        if mod_logs_channel:
                            log_embed = discord.Embed(
                                title="🔨 Automatic Ban",
                                description=f"**User:** {message.author.mention}\n**Reason:** {violation_type}\n**Message:** {message.content}",
                                color=discord.Color.red(),
                                timestamp=datetime.now(timezone.utc)
                            )
                            await mod_logs_channel.send(embed=log_embed)
                        
                    except Exception as e:
                        logger.error(f"Failed to ban user: {str(e)}")

            # Check warning count and take action if needed
            warning_count = await self.get_warning_count(user_id, guild_id)
            thresholds = self.config['moderation']['warning_thresholds']
            
            # Send warning count to mod-logs
            if mod_logs_channel:
                warning_embed = discord.Embed(
                    title="⚠️ Warning",
                    description=f"**User:** {message.author.mention}\n**Warnings:** {warning_count}\n**Latest Warning:** {violation_type}",
                    color=discord.Color.yellow(),
                    timestamp=datetime.now(timezone.utc)
                )
                await mod_logs_channel.send(embed=warning_embed)
            
            if warning_count >= thresholds['ban']:
                try:
                    await message.author.ban(reason="Too many warnings")
                    logger.info(f"User {message.author} was banned for exceeding warning threshold")
                    
                    if mod_logs_channel:
                        ban_embed = discord.Embed(
                            title="🔨 Automatic Ban",
                            description=f"**User:** {message.author.mention}\n**Reason:** Too many warnings ({warning_count})",
                            color=discord.Color.red(),
                            timestamp=datetime.now(timezone.utc)
                        )
                        await mod_logs_channel.send(embed=ban_embed)
                        
                except Exception as e:
                    logger.error(f"Failed to ban user: {str(e)}")
            
            elif warning_count >= thresholds['kick']:
                try:
                    await message.author.kick(reason="Too many warnings")
                    logger.info(f"User {message.author} was kicked for exceeding warning threshold")
                    
                    if mod_logs_channel:
                        kick_embed = discord.Embed(
                            title="👢 Automatic Kick",
                            description=f"**User:** {message.author.mention}\n**Reason:** Too many warnings ({warning_count})",
                            color=discord.Color.orange(),
                            timestamp=datetime.now(timezone.utc)
                        )
                        await mod_logs_channel.send(embed=kick_embed)
                    
                except Exception as e:
                    logger.error(f"Failed to kick user: {str(e)}")

        except Exception as e:
            logger.error(f"Error in handle_violation: {str(e)}")

    @commands.command(name='report')
    async def report_message(self, ctx, message_id: int, *, reason: str = None):
        """Reports a message for review"""
        try:
            message = await ctx.channel.fetch_message(message_id)
            analysis = await self.analyze_message(message.content)
            
            if analysis['is_inappropriate'] or reason:
                await self.handle_violation(message, 'mild', reason or analysis['reason'])
                await ctx.send(f'✅ Message reported and reviewed.')
            else:
                await ctx.send('❌ The message does not contain any recognizable violations.')
        except Exception as e:
            await ctx.send('❌ Error reporting message. Check the message ID.')
            logger.error(f"Error reporting message: {e}")

    @commands.command(name='warnings')
    async def show_warnings(self, ctx, member: discord.Member = None):
        """Shows the warnings of a user"""
        target = member or ctx.author
        
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                'SELECT warning_level, reason, timestamp, message_content FROM warnings WHERE user_id = ? AND guild_id = ? ORDER BY timestamp DESC',
                (target.id, ctx.guild.id)
            ) as cursor:
                warnings = await cursor.fetchall()
        
        if not warnings:
            await ctx.send(f'✅ {target.mention} has no warnings.')
            return
            
        embed = discord.Embed(
            title=f"Warnings for {target.name}",
            color=discord.Color.orange()
        )
        
        for i, (level, reason, timestamp, content) in enumerate(warnings, 1):
            # Parse the ISO timestamp and format it
            try:
                warning_time = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                warning_time = timestamp
            
            embed.add_field(
                name=f"Warning {i} ({level})",
                value=f"**Time:** {warning_time}\n**Reason:** {reason}\n**Message:** {content}",
                inline=False
            )
        
        await ctx.send(embed=embed)

    @commands.command(name='clearwarnings')
    @commands.has_permissions(administrator=True)
    async def clear_warnings(self, ctx, member: discord.Member):
        """Clears all warnings of a user (only for administrators)"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                'DELETE FROM warnings WHERE user_id = ? AND guild_id = ?',
                (member.id, ctx.guild.id)
            )
            await db.commit()
            
        await ctx.send(f'✅ All warnings of {member.mention} have been cleared.')

    @commands.command(name='help')
    async def show_help(self, ctx):
        """Shows help for all commands"""
        embed = discord.Embed(
            title="ModGuard Help",
            description="Here are all available commands:",
            color=discord.Color.blue()
        )
        
        commands_info = {
            "report": "!report <message_id> [reason] - Reports a message for review",
            "warnings": "!warnings [@user] - Shows the warnings of a user",
            "clearwarnings": "!clearwarnings @user - Clears all warnings of a user (only Admin)",
            "help": "!help - Shows this help"
        }
        
        for cmd, desc in commands_info.items():
            embed.add_field(name=cmd, value=desc, inline=False)
            
        await ctx.send(embed=embed)

    @commands.command(name='kick')
    @commands.has_permissions(kick_members=True)
    async def kick_user(self, ctx, member: discord.Member, *, reason=None):
        """Kicks a user from the server"""
        try:
            await member.kick(reason=reason)
            await ctx.send(f'👢 {member.mention} has been kicked.\nReason: {reason or "No reason provided"}')
            logger.info(f"User {member} was kicked by {ctx.author}. Reason: {reason}")
        except discord.Forbidden:
            await ctx.send("❌ I don't have permission to kick this user.")
        except Exception as e:
            await ctx.send(f"❌ An error occurred: {str(e)}")
            logger.error(f"Error kicking user: {str(e)}")

    @commands.command(name='ban')
    @commands.has_permissions(ban_members=True)
    async def ban_user(self, ctx, member: discord.Member, *, reason=None):
        """Bans a user from the server"""
        try:
            await member.ban(reason=reason)
            await ctx.send(f'🔨 {member.mention} has been banned.\nReason: {reason or "No reason provided"}')
            logger.info(f"User {member} was banned by {ctx.author}. Reason: {reason}")
        except discord.Forbidden:
            await ctx.send("❌ I don't have permission to ban this user.")
        except Exception as e:
            await ctx.send(f"❌ An error occurred: {str(e)}")
            logger.error(f"Error banning user: {str(e)}")

    @commands.command(name='timeout')
    @commands.has_permissions(moderate_members=True)
    async def timeout_user(self, ctx, member: discord.Member, duration: int, unit='m', *, reason=None):
        """Timeouts a user for a specified duration
        
        Duration units: s (seconds), m (minutes), h (hours), d (days)
        Example: !timeout @user 10 m Spamming
        """
        if member.id == ctx.guild.owner_id:
            await ctx.send("❌ Cannot timeout the server owner.")
            return
        
        if member.top_role >= ctx.guild.me.top_role:
            await ctx.send("❌ Cannot timeout a member with a role higher than or equal to mine.")
            return
        
        try:
            # Convert duration to seconds
            seconds = self.convert_to_seconds(duration, unit)
            if seconds <= 0:
                await ctx.send("❌ Duration must be greater than 0.")
                return
            if seconds > 60 * 60 * 24 * 28:  # 28 days in seconds (Discord's max timeout)
                await ctx.send("❌ Duration cannot exceed 28 days.")
                return
            
            # Calculate end time
            until = discord.utils.utcnow() + timedelta(seconds=seconds)
            
            await member.timeout(until, reason=reason)
            await ctx.send(f'⏰ {member.mention} has been timed out for {duration}{unit}.\nReason: {reason or "No reason provided"}')
            logger.info(f"User {member} was timed out by {ctx.author} for {duration}{unit}. Reason: {reason}")
        except discord.Forbidden:
            await ctx.send("❌ I don't have permission to timeout this user.")
            logger.error(f"Failed to timeout user {member}: Missing Permissions")
        except Exception as e:
            await ctx.send(f"❌ An error occurred: {str(e)}")
            logger.error(f"Failed to timeout user {member}: {str(e)}")

    @commands.command(name='untimeout')
    @commands.has_permissions(moderate_members=True)
    async def remove_timeout(self, ctx, member: discord.Member):
        """Removes timeout from a user"""
        try:
            await member.edit(timed_out_until=None)
            await ctx.send(f'✅ Timeout removed from {member.mention}')
            logger.info(f"Timeout removed from {member} by {ctx.author}")
        except discord.Forbidden:
            await ctx.send("❌ I don't have permission to remove timeout from this user.")
        except Exception as e:
            await ctx.send(f"❌ An error occurred: {str(e)}")
            logger.error(f"Error removing timeout: {str(e)}")

    def convert_to_seconds(self, duration: int, unit: str) -> int:
        unit_mapping = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
        return duration * unit_mapping.get(unit.lower(), 60)  # Default to minutes if invalid unit

if __name__ == '__main__':
    bot = ModGuard()
    bot.run(os.getenv('DISCORD_TOKEN'))
