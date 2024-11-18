const mongoose = require('mongoose');

const PendingUserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    discordId: { type: String, required: true },
    status: { type: String, default: 'pending' } // 'pending', 'accepted', 'rejected'
});

module.exports = mongoose.model('PendingUser', PendingUserSchema);
