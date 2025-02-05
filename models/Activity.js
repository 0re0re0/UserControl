const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  lastLogin: { type: Date, default: Date.now },
  failedAttempts: { type: Number, default: 0 },
  isLoggedIn: { type: Boolean, default: false },
});

const Activity = mongoose.model('Activity', activitySchema);
module.exports = Activity;