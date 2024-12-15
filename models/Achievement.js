const mongoose = require('mongoose');

const achievementSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  icon: {
    type: String,
    required: true
  },
  earned: {
    type: Boolean,
    default: false
  },
  earnedDate: {
    type: Date
  },
  criteria: {
    type: Object,
    required: true
  }
}, { timestamps: true });

module.exports = mongoose.model('Achievement', achievementSchema);
