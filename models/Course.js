import mongoose from 'mongoose';

const milestoneSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  deadline: {
    type: String,
    required: true
  }
});

const courseSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true
  },
  provider: {
    type: String,
    required: true
  },
  duration: {
    type: String,
    required: true
  },
  totalQuizzes: {
    type: Number,
    default: 10
  },
  difficulty: {
    type: String,
    enum: ['Beginner', 'Intermediate', 'Advanced'],
    default: 'Beginner'
  },
  progress: {
    type: Number,
    default: 0
  },
  lastAccessed: {
    type: Date,
    default: Date.now
  },
  pace: {
    type: String,
    required: true
  },
  objectives: [{
    type: String,
    required: true
  }],
  deadline: {
    type: String,
    required: true
  },
  milestones: [milestoneSchema]
}, {
  timestamps: true
});

const Course = mongoose.model('Course', courseSchema);

export default Course;