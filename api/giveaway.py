import discord
from discord.ext import commands
import asyncio
import datetime
import re
from core.database import db

# ==============================================================================
# 🎨 BLAZECLOUD CONFIGURATION
# ==============================================================================

EMOJIS = {
    "gift": "<a:gift:1464886519071248528>",
    "arrow": "<a:arrow_arrow:1465707628100325570>", 
    "free": "<a:lightening:1473016346080968776>",
    "premium": "<a:premium:1473015632294449427>",
    "boost": "<a:boost:1473014640895332468>",
    "loading": "<:b_stop:1473957519625027657>",
    "success": "<a:blue_tick_b:1470630619280179345>",
    "error": "<:b_stop:1473957519625027657>",
    "warn": "<:b_stop:1473957519625027657>",
    "bell": "🔔"
}

FOOTER_TEXT = "BlazeCloud Gen • Powering Your Server"

class BlazeGen(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] BlazeCloud Systems Online")

    # --------------------------------------------------------------------------
    # 📌 EVENT: STICKY MESSAGE HANDLER
    # --------------------------------------------------------------------------
    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author.bot:
            return

        sticky_data = await db.db["stickies"].find_one({"channel_id": message.channel.id})
        if sticky_data:
            old_msg_id = sticky_data.get("last_msg_id")
            if old_msg_id:
                try:
                    old_msg = await message.channel.fetch_message(old_msg_id)
                    await old_msg.delete()
                except (discord.NotFound, discord.Forbidden):
                    pass

            embed = discord.Embed(
                description=sticky_data["message"], 
                color=0x00BFFF
            )
            embed.set_footer(text=" Sticky Message")
            
            new_msg = await message.channel.send(embed=embed)
            
            await db.db["stickies"].update_one(
                {"channel_id": message.channel.id},
                {"$set": {"last_msg_id": new_msg.id}}
            )

    # --------------------------------------------------------------------------
    # 🛠️ HELPER FUNCTIONS
    # --------------------------------------------------------------------------

    async def send_error(self, ctx, message_text, delay=7):
        """Deletes the user's command message and sends a temporary error."""
        try:
            await ctx.message.delete()
        except (discord.Forbidden, discord.NotFound):
            pass # Ignore if bot lacks permission or message is already gone
            
        # We use ctx.send instead of ctx.reply because the original message is deleted
        return await ctx.send(message_text, delete_after=delay)

    def parse_time(self, time_str: str) -> int:
        time_regex = re.compile(r"(\d+)([smhdw])")
        match = time_regex.match(time_str.lower())
        if not match:
            return None
        amount, unit = match.groups()
        amount = int(amount)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
        return amount * multipliers[unit]

    async def check_cooldown(self, user_id, guild_id, tier):
        config = await db.db["guild_configs"].find_one({"guild_id": guild_id})
        if not config or "cooldowns" not in config or tier not in config["cooldowns"]:
            return None 

        cooldown_seconds = config["cooldowns"][tier]
        
        usage = await db.db["gen_history"].find_one({
            "user_id": user_id, 
            "guild_id": guild_id, 
            "tier": tier
        })

        if usage:
            elapsed = (datetime.datetime.utcnow() - usage["last_used"]).total_seconds()
            if elapsed < cooldown_seconds:
                return cooldown_seconds - elapsed
        
        return None

    async def update_usage(self, user_id, guild_id, tier):
        await db.db["gen_history"].update_one(
            {"user_id": user_id, "guild_id": guild_id, "tier": tier},
            {"$set": {"last_used": datetime.datetime.utcnow()}},
            upsert=True
        )

    # --- 🔔 RESTOCK WEBHOOK HANDLER ---
    async def send_restock_webhook(self, guild, tier, service, count):
        try:
            config = await db.db["guild_configs"].find_one({"guild_id": guild.id})
            if not config or "restock_channel" not in config:
                return 

            channel_id = config["restock_channel"]
            channel = guild.get_channel(channel_id)
            if not channel: return

            webhooks = await channel.webhooks()
            webhook = next((w for w in webhooks if w.user == self.bot.user), None)
            if not webhook:
                webhook = await channel.create_webhook(name="Restock Notification", reason="Stock Alerts")

            tier_emoji = EMOJIS.get(tier, "⚡")
            embed = discord.Embed(
                title=f"{tier_emoji} {tier.title()} Generator Restocked",
                description=f"Fresh stock has been added to the **{tier.title()}** Vault.",
                color=0x2b2d31,
                timestamp=datetime.datetime.utcnow()
            )
            embed.add_field(name=f"{EMOJIS['arrow']} Service", value=f"**{service.title()}**", inline=True)
            embed.add_field(name=f"{EMOJIS['gift']} Quantity", value=f"**+{count} Units**", inline=True)
            embed.set_thumbnail(url=guild.icon.url if guild.icon else None)
            embed.set_footer(text=FOOTER_TEXT)

            await webhook.send(embed=embed)

        except Exception as e:
            print(f"Failed to send webhook: {e}")

    # --------------------------------------------------------------------------
    # 📌 COMMAND: !STICKY
    # --------------------------------------------------------------------------
    @commands.command(name="sticky")
    @commands.has_permissions(administrator=True)
    async def sticky(self, ctx, *, message: str = None):
        try:
            await ctx.message.delete()
        except discord.Forbidden:
            pass

        if not message or message.lower() in ["stop", "remove", "delete"]:
            await db.db["stickies"].delete_one({"channel_id": ctx.channel.id})
            return await ctx.send(f"{EMOJIS['success']} **Sticky message removed.**", delete_after=5)
        
        await db.db["stickies"].update_one(
            {"channel_id": ctx.channel.id},
            {"$set": {"message": message, "last_msg_id": None}},
            upsert=True
        )
        
        embed = discord.Embed(description=message, color=0x2b2d31)
        embed.set_footer(text="📌 Sticky Message")
        msg = await ctx.send(embed=embed)
        
        await db.db["stickies"].update_one(
            {"channel_id": ctx.channel.id},
            {"$set": {"last_msg_id": msg.id}}
        )

    # --------------------------------------------------------------------------
    # ⚙️ COMMAND: $SETUP (AUTO ROLES)
    # --------------------------------------------------------------------------
    @commands.command(name="setup")
    @commands.has_permissions(administrator=True)
    async def setup(self, ctx):
        msg = await ctx.send(f"{EMOJIS['loading']} **Initializing BlazeCloud Environment...**")

        roles_needed = {
            "free": ("Blaze Free", discord.Color.light_grey()),
            "premium": ("Blaze Premium", discord.Color.gold()),
            "boost": ("Blaze Booster", discord.Color.purple())
        }
        created_roles = {}
        for tier, (name, color) in roles_needed.items():
            role = discord.utils.get(ctx.guild.roles, name=name)
            if not role:
                role = await ctx.guild.create_role(name=name, color=color, reason="BlazeCloud Setup")
            created_roles[tier] = role.id

        await db.db["guild_configs"].update_one(
            {"guild_id": ctx.guild.id},
            {"$set": {"roles": created_roles}},
            upsert=True
        )

        embed = discord.Embed(title=f"{EMOJIS['success']} Setup Complete", color=0x43b581)
        embed.description = (
            "**Roles Created & Linked:**\n"
            f"{EMOJIS['free']} <@&{created_roles['free']}>\n"
            f"{EMOJIS['premium']} <@&{created_roles['premium']}>\n"
            f"{EMOJIS['boost']} <@&{created_roles['boost']}>\n\n"
            "**Next Step:** Set restock channel: `!restock #channel`\nAdd stock: `$add`"
        )
        await msg.delete()
        await ctx.send(embed=embed)

    # --------------------------------------------------------------------------
    # 🔔 COMMAND: !RESTOCK (SET CHANNEL)
    # --------------------------------------------------------------------------
    @commands.command(name="restock")
    @commands.has_permissions(administrator=True)
    async def set_restock_channel(self, ctx, channel: discord.TextChannel):
        await db.db["guild_configs"].update_one(
            {"guild_id": ctx.guild.id},
            {"$set": {"restock_channel": channel.id}},
            upsert=True
        )
        await self.send_error(ctx, f"{EMOJIS['success']} Restock alerts will now be sent to {channel.mention}", delay=10)

    # --------------------------------------------------------------------------
    # ⏱️ COMMAND: !SL (SLOWMODE)
    # --------------------------------------------------------------------------
    @commands.command(name="sl", aliases=["slowmode"])
    @commands.has_permissions(administrator=True)
    async def slowmode(self, ctx, tier: str, time_str: str):
        tier = tier.lower()
        if tier not in ["free", "premium", "boost"]:
            return await self.send_error(ctx, f"{EMOJIS['error']} Tier must be `free`, `premium`, or `boost`.")

        seconds = self.parse_time(time_str)
        if seconds is None:
            return await self.send_error(ctx, f"{EMOJIS['error']} Invalid time format. Use `10m`, `1h`, `30s`.")

        await db.db["guild_configs"].update_one(
            {"guild_id": ctx.guild.id},
            {"$set": {f"cooldowns.{tier}": seconds}},
            upsert=True
        )

        await self.send_error(ctx, f"{EMOJIS['success']} **{tier.title()}** cooldown set to `{time_str}`.", delay=10)

    # --------------------------------------------------------------------------
    # 💎 COMMAND: $GEN
    # --------------------------------------------------------------------------
    @commands.command(name="gen")
    async def gen(self, ctx, tier: str = None, service: str = None):
        
        # ERROR DELETES BOT & USER MSG AFTER 7 SECONDS
        if not tier or not service:
            return await self.send_error(ctx, f"{EMOJIS['error']} Usage: `$gen <tier> <service>`")

        tier = tier.lower()
        service = service.lower()
        
        if tier not in ["free", "premium", "boost"]:
            return await self.send_error(ctx, f"{EMOJIS['error']} Invalid Tier. Use free, premium, or boost.")

        # 1. CHECK ROLES
        config = await db.db["guild_configs"].find_one({"guild_id": ctx.guild.id})
        if config and "roles" in config:
            required_role_id = config["roles"].get(tier)
            role = ctx.guild.get_role(required_role_id)
            if role and role not in ctx.author.roles:
                return await self.send_error(ctx, f"{EMOJIS['error']} You need the {role.mention} role to use this generator.")

        # 2. CHECK COOLDOWN
        remaining = await self.check_cooldown(ctx.author.id, ctx.guild.id, tier)
        if remaining:
            return await self.send_error(ctx, f"{EMOJIS['loading']} You are moving too fast bruh!! Wait `{int(remaining)}s` before generating again.")

        # 3. GET STOCK (GUILD SPECIFIC)
        account = await db.db["accounts"].find_one_and_delete({
            "guild_id": ctx.guild.id, 
            "tier": tier,
            "service": service
        })

        if not account:
            return await self.send_error(ctx, f"{EMOJIS['error']} **{service.title()}** is out of stock or service doesn't exist. Check spelling.")

        # 4. DELIVERY
        try:
            # Send to DM
            dm_embed = discord.Embed(
                title=f"{EMOJIS['arrow']} BlazeCloud Dispatch",
                description=f"**Service:** {service.upper()}\n**Tier:** {tier.upper()}",
                color=0x2b2d31,
                timestamp=datetime.datetime.utcnow()
            )
            dm_embed.add_field(name="Credentials", value=f"```yaml\n{account['data']}\n```", inline=False)
            dm_embed.add_field(name="Note", value="Want daily Hits for 100+ accounts? Buy a stock server!!", inline=False)
            dm_embed.set_footer(text=FOOTER_TEXT, icon_url=ctx.guild.icon.url if ctx.guild.icon else None)
            
            await ctx.author.send(embed=dm_embed)
            
            # SUCCESS! We keep the User's Message and reply to it permanently.
            success_embed = discord.Embed(
                description=f"{EMOJIS['success']} **{ctx.author.mention}**, I have sent the **{service.upper()}** account to your DMs!",
                color=0x43b581
            )
            await ctx.reply(embed=success_embed)
            
            await self.update_usage(ctx.author.id, ctx.guild.id, tier)

        except discord.Forbidden:
            await db.db["accounts"].insert_one(account)
            await self.send_error(ctx, f"{EMOJIS['warn']} Enable your DMs to receive accounts.")

    # --------------------------------------------------------------------------
    # 📦 COMMAND: $STOCK
    # --------------------------------------------------------------------------
    @commands.command(name="stock") 
    async def stock(self, ctx):
        pipeline = [
            {"$match": {"guild_id": ctx.guild.id}}, 
            {"$group": {"_id": {"tier": "$tier", "service": "$service"}, "count": {"$sum": 1}}},
            {"$sort": {"_id.service": 1}}
        ]
        results = await db.db["accounts"].aggregate(pipeline).to_list(length=1000)

        embed = discord.Embed(
            title=None,
            description=f"## {EMOJIS['gift']} BlazeCloud Inventory {EMOJIS['gift']}\n+ Active stock for **{ctx.guild.name}**\n━━━━━━━━━━━━━━━━━━━━━━",
            color=0x2b2d31
        )

        if not results:
            embed.description = f"{EMOJIS['error']} **Inventory Empty.** Ask an admin to restock!"
        else:
            vaults = {"free": [], "premium": [], "boost": []}

            for item in results:
                tier = item["_id"]["tier"]
                service = item["_id"]["service"]
                count = item["count"]
                
                line = f"{EMOJIS['arrow']} {service.title()} → **[ `{count}` ]**"
                if tier in vaults:
                    vaults[tier].append(line)

            for tier, lines in vaults.items():
                if lines:
                    header_emoji = EMOJIS.get(tier, "🔹")
                    embed.add_field(name=f"{header_emoji} __**{tier.title()} Vault**__", value="\n".join(lines) + "\n", inline=False)

        embed.set_footer(text=FOOTER_TEXT)
        await ctx.send(embed=embed)

    # --------------------------------------------------------------------------
    # ➕ COMMAND: $ADD
    # --------------------------------------------------------------------------
    @commands.command(name="add")
    @commands.has_permissions(administrator=True)
    async def add(self, ctx, tier: str, service: str):
        tier, service = tier.lower(), service.lower()
        
        if not ctx.message.attachments:
            return await self.send_error(ctx, f"{EMOJIS['error']} Attach a .txt file.")

        attachment = ctx.message.attachments[0]
        
        try:
            content_bytes = await attachment.read()
            try:
                content = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content = content_bytes.decode("latin-1")

            lines = content.splitlines()
            
            data_list = []
            for line in lines:
                if line.strip():
                    data_list.append({
                        "guild_id": ctx.guild.id, 
                        "tier": tier,
                        "service": service,
                        "data": line.strip(),
                        "added_at": datetime.datetime.utcnow()
                    })

            if data_list:
                await db.db["accounts"].insert_many(data_list)
                await self.send_error(ctx, f"{EMOJIS['success']} Added `{len(data_list)}` accounts to **{ctx.guild.name}** stock.", delay=10)
                
                await self.send_restock_webhook(ctx.guild, tier, service, len(data_list))
            else:
                await self.send_error(ctx, f"{EMOJIS['error']} File empty.")

        except Exception as e:
            await self.send_error(ctx, f"❌ Error processing file: {e}")

    # --------------------------------------------------------------------------
    # 🗑️ COMMAND: $NUKE
    # --------------------------------------------------------------------------
    @commands.command(name="nuke")
    @commands.has_permissions(administrator=True)
    async def nuke(self, ctx, tier: str, service: str):
        result = await db.db["accounts"].delete_many({
            "guild_id": ctx.guild.id,
            "tier": tier.lower(),
            "service": service.lower()
        })
        await self.send_error(ctx, f"🗑️ Nuked `{result.deleted_count}` accounts from **{ctx.guild.name}**.", delay=10)

async def setup(bot):
    await bot.add_cog(BlazeGen(bot))
