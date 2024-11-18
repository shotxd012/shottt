const express = require('express');
const { ChannelType, GuildExplicitContentFilter, GuildNSFWLevel, GuildVerificationLevel, PermissionsBitField } = require('discord.js');
const session = require('express-session');
const os = require('os');
const { exec } = require('child_process');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cron = require('node-cron');
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const path = require('path'); 
const { Client, GatewayIntentBits } = require('discord.js');
const mongoose = require('mongoose');
const Levels = require(`${process.cwd()}/src/database/models/functions`);
const Schema = require(`${process.cwd()}/src/database/models/channelList`);
const Blacklist = require(`${process.cwd()}/src/database/models/blacklist`);
const inviteMessages = require(`${process.cwd()}/src/database/models/inviteMessages`);
const welcomeChannel = require(`${process.cwd()}/src/database/models/welcomeChannels`);
const leaveChannel = require(`${process.cwd()}/src/database/models/leaveChannels`);
const boostChannels = require(`${process.cwd()}/src/database/models/boostChannels`);
const logChannels = require(`${process.cwd()}/src/database/models/logChannels`);
const PingHistory = require(`${process.cwd()}/src/database/models/pingHistory`);
const { inviteURL, supportServer, port } = require(`${process.cwd()}/src/config/web.config.json`);
const PendingUser = require(`${process.cwd()}/src/database/models/PendingUser`);
const AdminUser = require(`${process.cwd()}/src/database/models/AdminUser`);
require('dotenv').config();
const bodyParser = require('body-parser');
const app = express();
const fs = require('fs');
const db = require(`${process.cwd()}/src/db`);

mongoose.set('strictQuery', false);

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
});

mongoose.connection.on('error', err => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.once('open', () => {
    console.log(` mongoose connected !`);

});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((obj, done) => {
    done(null, obj);
});
app.use(session({
    secret: 'afgsrwrfwrgrg',
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));



// contact area 
app.post('/submit-contact', (req, res) => {
    const { discordName, email, subject, message, bugReport } = req.body;

    const query = `INSERT INTO contacts (discord_name, email, subject, message, bug_report) VALUES (?, ?, ?, ?, ?)`;
    db.query(query, [discordName, email, subject, message, bugReport || null], (err, result) => {
        if (err) {
            console.error(err);
            res.json({ success: false });
        } else {
            res.json({ success: true });
        }
    });
});

app.get('/admin/contact-messages', (req, res) => {
    const query = `SELECT * FROM contacts ORDER BY created_at DESC`;
    db.query(query, (err, results) => {
        if (err) {
            console.error(err);
            res.status(500).send('Error fetching contact messages.');
        } else {
            res.render('contact-messages', { messages: results });
        }
    });
});


const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
    ]
});

client.login(process.env.BOT_TOKEN);

cron.schedule('* * * * *', async () => {
    try {
      const ping = client.ws.ping;
      if (isNaN(ping)) {
        throw new Error('Invalid ping value: NaN');
      }
      await PingHistory.create({ ping });
      console.log('Ping recorded:', ping);
    } catch (error) {
      console.error('Error recording ping:', error);
    }
  });


// fetchBotData
async function fetchBotData() {
    try {
      const totalGuilds = client.guilds.cache.size;
      const totalMembers = client.guilds.cache.reduce((acc, guild) => acc + guild.memberCount, 0);
      const totalChannels = client.channels.cache.size;
      const ping = client.ws.ping;
  
      function formatUptime(ms) {
        if (!ms) return 'N/A';
        const days = Math.floor(ms / (24 * 60 * 60 * 1000));
        const daysMs = ms % (24 * 60 * 60 * 1000);
        const hours = Math.floor(daysMs / (60 * 60 * 1000));
        const hoursMs = ms % (60 * 60 * 1000);
        const minutes = Math.floor(hoursMs / (60 * 1000));
        const minutesMs = ms % (60 * 1000);
        const seconds = Math.floor(minutesMs / 1000);
        return `${days}d ${hours}h ${minutes}m ${seconds}s`;
      }
  
      const uptime = formatUptime(client.uptime);
      await PingHistory.create({ ping });
  
      return {
        totalGuilds,
        totalMembers,
        totalChannels,
        uptime,
        ping
      };
    } catch (error) {
      console.error('Error fetching bot data:', error);
      return null;
    }
  }
  


// auth access
const scopes = ['identify', 'guilds'];

passport.use(new DiscordStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    scope: scopes
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let guilds;
        let retries = 3;
        while (retries > 0) {
            try {
                const response = await axios.get('https://discord.com/api/v10/users/@me/guilds', {
                    headers: {
                        Authorization: `Bearer ${accessToken}`
                    }
                });
                guilds = response.data;
                break;
            } catch (error) {
                if (error.response && error.response.status === 429) {
                    const retryAfter = error.response.headers['retry-after'];
                    console.log(`Rate limited, retrying after ${retryAfter} seconds`);
                    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
                } else {
                    throw error;
                }
            }
            retries--;
        }

        if (!guilds) throw new Error('Failed to fetch guilds');

        const adminGuilds = guilds.filter(guild => (guild.permissions & 0x8) === 0x8);

        profile.guilds = adminGuilds;
        return done(null, profile);
    } catch (error) {
        return done(error, null);
    }
}));

// admin login area 

function checkAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
    res.render('adminlogin', { error: null });
});

app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await AdminUser.findOne({ username, password });

        if (user) {
            req.session.user = user; 
            res.redirect('/admin');
        } else {
            res.render('adminlogin', { error: 'Invalid username or password' });
        }
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/admin', checkAuthenticated, authshot, (req, res) => {
    res.render('admin', { user: req.session.user });
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        res.redirect('/admin/login');
    });
});
app.get('/admin/botservers', checkAuthenticated, (req, res) => {
    const servers = client.guilds.cache.map(guild => ({
        id: guild.id,
        name: guild.name,
        memberCount: guild.memberCount
    }));

    res.render('botservers', { user: req.session.user, servers });
});

app.get('/admin/botstatus', checkAuthenticated, async (req, res) => {
  try {
    const pingHistory = await PingHistory.find().sort({ timestamp: -1 }).limit(100);
    const botData = await fetchBotData();
    if (!botData) {
      return res.status(500).send('Error fetching bot data');
    }
    res.render('botstatus', { botData, pingHistory });
  } catch (error) {
    console.error('Error fetching status data:', error);
    res.status(500).send('Internal Server Error');
  }
});


//admin login area 


app.get('/admin/totalapplications', checkAuthenticated, async (req, res) => {
    try {
        const pendingApplications = await PendingUser.find({ status: 'pending' });
        const acceptedApplications = await AdminUser.find({});
        const rejectedApplications = await PendingUser.find({ status: 'rejected' });

        res.render('totalapplications', {
            user: req.session.user,
            pending: pendingApplications,
            accepted: acceptedApplications,
            rejected: rejectedApplications
        });
    } catch (err) {
        console.error('Error fetching total applications:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/admin/applications/delete/:id', checkAuthenticated, async (req, res) => {
    const { id } = req.params;

    try {
        await AdminUser.findByIdAndDelete(id);
        res.redirect('/admin/totalapplications');
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).send('Internal Server Error');
    }
});

// dc login
app.use(express.urlencoded({ extended: true }));

app.get('/login', passport.authenticate('discord'));

app.get('/callback', passport.authenticate('discord', {
    failureRedirect: '/'
}), (req, res) => {
    res.redirect('/');
});


// profile 
app.get('/profile', checkAuth, async (req, res) => {
    try {
        const response = await fetch('https://vazha.fun/api/user', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${req.session.token}` 
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch profile data');
        }

        const data = await response.json();
        res.render('profile', {
            user: req.user,
            totalCommands: data.totalCommands,
            todayCommands: data.todayCommands,
            recentCommand: data.recentCommand,
            memberSince: data.memberSince
        });
    } catch (error) {
        console.error(error);
        res.render('profile', {
            user: req.user,
            totalCommands: 'N/A',
            todayCommands: 'N/A',
            recentCommand: 'N/A',
            memberSince: 'N/A'
        });
    }
});

app.get('/ping-history', async (req, res) => {
    try {
      const now = new Date();
      const hundredMinutesAgo = new Date(now.getTime() - 100 * 60 * 1000);
      const pingHistory = await PingHistory.find({ timestamp: { $gte: hundredMinutesAgo } })
                                            .sort({ timestamp: -1 })
                                            .limit(10);
      const data = pingHistory.map(record => ({
        timestamp: record.timestamp,
        ping: record.ping
      }));
  
      res.json(data.reverse());
    } catch (error) {
      console.error('Error fetching ping history:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

app.get('/status', async (req, res) => {
  try {
    const pingHistory = await PingHistory.find().sort({ timestamp: -1 }).limit(100);
    const botData = await fetchBotData();
    if (!botData) {
      return res.status(500).send('Error fetching bot data');
    }
    res.render('status', { botData, pingHistory });
  } catch (error) {
    console.error('Error fetching status data:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/admin-servers', checkAuth, (req, res) => {
    res.render('admin-servers', {
        user: req.user
    });
});

app.get('/invite', async (req, res) => {
  res.status(200)
  res.redirect(inviteURL)
})

app.get('/supportServer', async (req, res) => {
  res.status(200)
  res.redirect(supportServer)
})

app.get('/server/:id', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    try {
        const guild = await client.guilds.fetch(guildId);
        const member = await guild.members.fetch(req.user.id);
        if (!member.permissions.has(PermissionsBitField.Flags.Administrator)) {
            return res.redirect('/no-access');
        }
        const { members, channels, emojis, roles, stickers } = guild;
        const sortedRoles = roles.cache
            .map((role) => role)
            .slice(1, roles.cache.size)
            .sort((a, b) => b.position - a.position);
        const userRoles = sortedRoles.filter((role) => !role.managed);
        const managedRoles = sortedRoles.filter((role) => role.managed);
        const botCount = members.cache.filter((member) => member.user.bot).size;
        
        const maxDisplayRoles = (roles, maxFieldLength = 1024) => {
            let totalLength = 0;
            const result = [];
    
            for (const role of roles) {
                const roleString = `<@&${role.id}>`;
                if (roleString.length + totalLength > maxFieldLength) break;
                totalLength += roleString.length + 1;
                result.push(roleString);
            }
    
            return result.length;
        };

        const splitPascal = (string, separator) =>
                string.split(/(?=[A-Z])/).join(separator);
        const toPascalCase = (string, separator = false) => {
            const pascal =
                string.charAt(0).toUpperCase() +
                string.slice(1).toLowerCase().replace(/[^a-zA-Z0-9]+(.)/g, (match, chr) => chr.toUpperCase());
            return separator ? splitPascal(pascal, separator) : pascal;
        };

        const getChannelTypeSize = (type) =>
            channels.cache.filter((channel) => type.includes(channel.type)).size;

        const totalChannels = getChannelTypeSize([
            ChannelType.GuildText,
            ChannelType.GuildNews,
            ChannelType.GuildVoice,
            ChannelType.GuildStageVoice,
            ChannelType.GuildForum,
            ChannelType.GuildPublicThread,
            ChannelType.GuildPrivateThread,
            ChannelType.GuildNewsThread,
            ChannelType.GuildCategory,
        ]);

        const serverDetails = {
            description: guild.description || "None",
            createdTimestamp: guild.createdTimestamp,
            ownerId: guild.ownerId,
            language: new Intl.DisplayNames(["en"], { type: "language" }).of(guild.preferredLocale),
            vanityURLCode: guild.vanityURLCode || "None",
            features: guild.features?.map((feature) => toPascalCase(feature, " "))?.join(", ") || "None",
            explicitFilter: splitPascal(GuildExplicitContentFilter[guild.explicitContentFilter], " "),
            nsfwLevel: splitPascal(GuildNSFWLevel[guild.nsfwLevel], " "),
            verificationLevel: splitPascal(GuildVerificationLevel[guild.verificationLevel], " "),
            memberCount: guild.memberCount,
            botCount: botCount,
            userRoles: userRoles.slice(0, maxDisplayRoles(userRoles)).map(role => role.name).join(", ") || "None",
            managedRoles: managedRoles.slice(0, maxDisplayRoles(managedRoles)).map(role => role.name).join(", ") || "None",
            totalChannels: totalChannels,
            textChannels: getChannelTypeSize([ChannelType.GuildText, ChannelType.GuildForum, ChannelType.GuildNews]),
            voiceChannels: getChannelTypeSize([ChannelType.GuildVoice, ChannelType.GuildStageVoice]),
            threads: getChannelTypeSize([ChannelType.GuildPublicThread, ChannelType.GuildPrivateThread, ChannelType.GuildNewsThread]),
            categories: getChannelTypeSize([ChannelType.GuildCategory]),
            animatedEmojis: emojis.cache.filter((emoji) => emoji.animated).size,
            staticEmojis: emojis.cache.filter((emoji) => !emoji.animated).size,
            stickers: stickers.cache.size,
            premiumTier: guild.premiumTier || "None",
            premiumSubscriptionCount: guild.premiumSubscriptionCount,
            premiumSubscriberCount: guild.members.cache.filter((member) => member.roles.premiumSubscriberRole).size,
            premiumSinceCount: guild.members.cache.filter((member) => member.premiumSince).size,
            bannerURL: guild.bannerURL(),
            
        };
		const logChannelSetting = await logChannels.findOne({ Guild: guildId }).exec();
		const logEnabled = logChannelSetting ? true : false;
		const logChannelId = logChannelSetting ? logChannelSetting.Channel : '';
		const logChannelName = logChannelSetting ? guild.channels.cache.get(logChannelId)?.name : '';

        const memberCount = guild.memberCount;
        const channelCount = guild.channels.cache.size;

        const settings = await Levels.findOne({ Guild: guildId }).exec();
        const levelsEnabled = settings ? settings.Levels : false;
        const antilinksEnabled = settings ? settings.AntiLinks : false;
        const antiinviteEnabled = settings ? settings.AntiInvite : false;
        const antispamEnabled = settings ? settings.AntiSpam : false;

        const welcomeChannelSetting = await welcomeChannel.findOne({ Guild: guildId }).exec();
        const welcomeEnabled = welcomeChannelSetting ? true : false;
        const welcomeChannelId = welcomeChannelSetting ? welcomeChannelSetting.Channel : '';
        const welcomeChannelName = welcomeChannelSetting ? guild.channels.cache.get(welcomeChannelId)?.name : '';

        const leaveChannelSetting = await leaveChannel.findOne({ Guild: guildId }).exec();
        const leaveEnabled = leaveChannelSetting ? true : false;
        const leaveChannelName = leaveChannelSetting ? guild.channels.cache.get(leaveChannelSetting.Channel)?.name : '';

        const boostChannelSetting = await boostChannels.findOne({ Guild: guildId }).exec();
        const boostEnabled = boostChannelSetting ? true : false;
        const boostChannelName = boostChannelSetting ? guild.channels.cache.get(boostChannelSetting.Channel)?.name : '';

        const inviteMessagesSetting = await inviteMessages.findOne({ Guild: guildId }).exec();
        const welcomeMessage = inviteMessagesSetting ? inviteMessagesSetting.inviteJoin : '';

        const blacklistData = await Blacklist.findOne({ Guild: guildId }).exec();
        const blacklistedWords = blacklistData ? blacklistData.Words : [];

        const allowedChannelsData = await Schema.findOne({ Guild: guildId }).exec();
        const allowedChannels = allowedChannelsData ? allowedChannelsData.Channels.map(channelId => ({
            id: channelId,
            name: guild.channels.cache.get(channelId)?.name
        })) : [];

        res.render('server', {
            user: req.user,
            guild: guild,
          	logEnabled: logEnabled,
    		logChannelName: logChannelName,
            memberCount: memberCount,
            channelCount: channelCount,
            serverDetails,
            levelsEnabled: levelsEnabled,
            antilinksEnabled: antilinksEnabled,
            antiinviteEnabled: antiinviteEnabled,
            antispamEnabled: antispamEnabled,
            welcomeEnabled: welcomeEnabled,
            welcomeChannelName: welcomeChannelName,
            welcomeMessage: welcomeMessage,
            welcomeChannelId: welcomeChannelId,
            leaveEnabled: leaveEnabled,
            leaveChannelName: leaveChannelName,
            boostEnabled: boostEnabled,
            boostChannelName: boostChannelName,
            blacklistedWords: blacklistedWords,
            allowedChannels: allowedChannels
        });
    } catch (error) {
        if (error.code === 10004) {
            const inviteLink = `https://discord.com/oauth2/authorize?client_id=${client.user.id}&scope=bot&permissions=8`;
            return res.redirect(inviteLink);
        } else {
            console.error('Error fetching guild:', error);
            res.status(500).render('500', {
                message: 'Internal Server Error'
            });
        }
    }
});


app.get('/no-access', (req, res) => {
    res.render('no-access', {
        message: '403, You do not have admin access to this server.'
    });
});



app.post('/server/:id/settings', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    const { levels, antilinks, antiinvite, antispam } = req.body;

    try {
        const settings = {
            Levels: levels === 'enable',
            AntiLinks: antilinks === 'enable',
            AntiInvite: antiinvite === 'enable',
            AntiSpam: antispam === 'enable'
        };
        await Levels.findOneAndUpdate(
            { Guild: guildId },
            settings,
            { upsert: true, new: true }
        ).exec();

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.json({ success: false });
    }
});

app.post('/server/:id/add-channel', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    const { channel } = req.body;

    try {
        let data = await Schema.findOne({ Guild: guildId });
        if (data) {
            if (data.Channels.includes(channel)) {
                return res.json({ success: false, message: 'Channel already exists' });
            }
            data.Channels.push(channel);
            await data.save();
        } else {
            await new Schema({
                Guild: guildId,
                Channels: [channel]
            }).save();
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding channel:', error);
        res.json({ success: false });
    }
});

app.post('/server/:id/log-channel', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    const { log, channel } = req.body;

    try {
        if (log === 'enable') {
            await logChannels.findOneAndUpdate(
                { Guild: guildId },
                { Guild: guildId, Channel: channel },
                { upsert: true }
            );
        } else {
            await logChannels.findOneAndDelete({ Guild: guildId });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating log channel:', error);
        res.json({ success: false });
    }
});

app.get('/server/:id/logs', checkAuth, async (req, res) => {
    const guildId = req.params.id;

    const query = `SELECT * FROM guild_logs WHERE guild_id = ? ORDER BY log_timestamp DESC LIMIT 50`;
    db.query(query, [guildId], (err, results) => {
        if (err) {
            console.error('MySQL error: ', err);
            res.json({ success: false, logs: [] });
        } else {
            res.json({ success: true, logs: results });
        }
    });
});



app.post('/server/:id/remove-channel', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    const { channel } = req.body;

    try {
        let data = await Schema.findOne({ Guild: guildId });
        if (data) {
            if (!data.Channels.includes(channel)) {
                return res.json({ success: false, message: 'Channel does not exist' });
            }
            data.Channels = data.Channels.filter(ch => ch !== channel);
            await data.save();
        } else {
            return res.json({ success: false, message: 'No data found for this guild' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error removing channel:', error);
        res.json({ success: false });
    }
});


app.post('/server/:guildId/welcome-channel', async (req, res) => {
    const { guildId } = req.params;
    const { welcome, channel } = req.body;
    try {
        if (welcome === 'enable') {
            await welcomeChannel.findOneAndUpdate({ Guild: guildId }, { Channel: channel }, { upsert: true });
        } else {
            await welcomeChannel.findOneAndDelete({ Guild: guildId });
        }
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.json({ success: false });
    }
});

app.post('/server/:guildId/welcome-message', async (req, res) => {
    const { guildId } = req.params;
    const { message } = req.body;
    try {
        let data = await inviteMessages.findOne({ Guild: guildId });
        if (data) {
            data.inviteJoin = message;
            await data.save();
        } else {
            await new inviteMessages({
                Guild: guildId,
                inviteJoin: message
            }).save();
        }
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.json({ success: false });
    }
});

app.post('/server/:guildId/boost-channel', async (req, res) => {
    const { guildId } = req.params;
    const { boost, channel } = req.body;
    try {
        if (boost === 'enable') {
            await boostChannels.findOneAndUpdate({ Guild: guildId }, { Channel: channel }, { upsert: true });
        } else {
            await boostChannels.findOneAndDelete({ Guild: guildId });
        }
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.json({ success: false });
    }
});


app.post('/server/:id/remove-word', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    const { word } = req.body;

    try {
        let data = await Blacklist.findOne({ Guild: guildId });
        if (data) {
            if (!data.Words.includes(word)) {
                return res.json({ success: false, message: 'Word does not exist' });
            }
            data.Words = data.Words.filter(w => w !== word);
            await data.save();
        } else {
            return res.json({ success: false, message: 'No data found for this guild' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error removing word:', error);
        res.json({ success: false });
    }
});

app.post('/server/:id/add-word', checkAuth, async (req, res) => {
    const guildId = req.params.id;
    const { word } = req.body;

    try {
        let data = await Blacklist.findOne({ Guild: guildId });
        if (data) {
            if (data.Words.includes(word)) {
                return res.json({ success: false, message: 'Word already exists' });
            }
            data.Words.push(word);
            await data.save();
        } else {
            await new Blacklist({
                Guild: guildId,
                Words: [word]
            }).save();
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding word:', error);
        res.json({ success: false });
    }
});
app.post('/server/:guildId/leave-channel', async (req, res) => {
    const { guildId } = req.params;
    const { leave, channel } = req.body;
    try {
        if (leave === 'enable') {
            await leaveChannel.findOneAndUpdate({ Guild: guildId }, { Channel: channel }, { upsert: true });
        } else {
            await leaveChannel.findOneAndDelete({ Guild: guildId });
        }
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.json({ success: false });
    }
});

app.get('/logout', (req, res) => {
    req.logout(err => {
        if (err) return next(err);
        res.redirect('/');
    });
});

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user
    });
});

app.get('/ping-log', (req, res) => {
    res.render('ping-log');
});

app.get('/terms', (req, res) => {
    res.render('terms');
});

app.get('/commands', (req, res) => {
    res.render('commands');
});

app.get('/policy', (req, res) => {
    res.render('policy');
});

app.use((req, res, next) => {
    res.status(404).render('404');
});

function checkAuth(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}


app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).render('500', {
        message: 'Internal Server Error'
    });
});


// listening 
app.listen(port, () => {
    console.log('vazha ---> WEB connected!');
});

module.exports = app;
