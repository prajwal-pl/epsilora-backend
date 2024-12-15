import mongoose from 'mongoose';

const milestoneProgressSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'Course'
  },
  milestoneIndex: {
    type: Number,
    required: true
  },
  completed: {
    type: Boolean,
    required: true,
    default: false
  },
  completedAt: {
    type: Date,
    default: null
  }
}, { timestamps: true });

// Create a compound index for unique milestone progress per user and milestone
milestoneProgressSchema.index({ userId: 1, courseId: 1, milestoneIndex: 1 }, { unique: true });

const MilestoneProgress = mongoose.model('MilestoneProgress', milestoneProgressSchema);

export default MilestoneProgress;
