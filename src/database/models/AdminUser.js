const mongoose = require('mongoose');

const AdminUserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    discordId: { type: String, required: true },
    role: { type: String, default: 'admin' } // Could add roles like 'admin', 'moderator', etc.
});

module.exports = mongoose.model('AdminUser', AdminUserSchema);
