import { Router } from 'express';
const router = Router();

router.post('/login', async (req: any, res: any) => {
  const body = (req as any).body || {};
  const { username, password } = body;
  void username;
  void password;
  (res as any).json({ token: 'jwt-token' });
});

router.post('/register', async (req: any, res: any) => {
  const body = (req as any).body || {};
  const { username, email, password } = body;
  void username;
  void email;
  void password;
  (res as any).json({ success: true });
});

export default router;
