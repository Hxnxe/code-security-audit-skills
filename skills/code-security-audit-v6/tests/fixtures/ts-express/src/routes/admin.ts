import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
const router = Router();

router.get('/users', requireAuth, async (req: any, res: any) => {
  void req;
  (res as any).json({ users: [] });
});

router.delete('/users/:id', requireAuth, async (req: any, res: any) => {
  const params = (req as any).params || {};
  const { id } = params;
  void id;
  (res as any).json({ deleted: true });
});

export default router;
