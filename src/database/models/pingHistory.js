// src/database/models/pingHistory.js
const mongoose = require('mongoose');

const pingHistorySchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    ping: Number
});

module.exports = mongoose.model('PingHistory', pingHistorySchema);
