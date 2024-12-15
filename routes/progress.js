import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import MilestoneProgress from '../models/MilestoneProgress.js';

const router = express.Router();

// Get all milestone progress for the authenticated user
router.get('/milestones', authenticateToken, async (req, res) => {
  try {
    const progress = await MilestoneProgress.find({ userId: req.user.id });
    res.json(progress.map(p => ({
      courseId: p.courseId.toString(),
      milestoneIndex: p.milestoneIndex,
      completed: p.completed
    })));
  } catch (error) {
    console.error('Error fetching milestone progress:', error);
    res.status(500).json({ message: 'Failed to fetch milestone progress' });
  }
});

// Update milestone progress
router.post('/milestones', authenticateToken, async (req, res) => {
  try {
    const { courseId, milestoneIndex, completed } = req.body;

    const progress = await MilestoneProgress.findOneAndUpdate(
      {
        userId: req.user.id,
        courseId,
        milestoneIndex
      },
      {
        $set: {
          completed,
          completedAt: completed ? new Date() : null
        }
      },
      {
        new: true,
        upsert: true
      }
    );

    res.json({
      courseId: progress.courseId.toString(),
      milestoneIndex: progress.milestoneIndex,
      completed: progress.completed
    });
  } catch (error) {
    console.error('Error updating milestone progress:', error);
    res.status(500).json({ message: 'Failed to update milestone progress' });
  }
});

export default router;
