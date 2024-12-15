import mongoose from 'mongoose';

const quizSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  score: {
    type: Number,
    required: true
  },
  totalQuestions: {
    type: Number,
    required: true
  },
  difficulty: {
    type: String,
    enum: ['Easy', 'Medium', 'Hard'],
    required: true
  },
  questions: [{
    question: String,
    correctAnswer: String,
    userAnswer: String,
    isCorrect: Boolean,
    timeSpent: Number
  }],
  date: {
    type: Date,
    default: Date.now
  },
  timeSpent: {
    type: Number,
    required: true
  },
  aiAssistanceUsed: {
    type: Boolean,
    default: false
  }
}, { timestamps: true });

// Calculate percentage score
quizSchema.virtual('percentageScore').get(function() {
  return (this.score / this.totalQuestions) * 100;
});

// Add indexes for faster querying
quizSchema.index({ userId: 1, date: -1 });
quizSchema.index({ courseId: 1 });

const Quiz = mongoose.model('Quiz', quizSchema);
export default Quiz;
