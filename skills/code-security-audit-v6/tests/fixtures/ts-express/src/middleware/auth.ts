export function requireAuth(req: any, res: any, next: () => void) {
  const token = (req as any).headers?.authorization;
  if (!token) {
    return (res as any).status(401).json({ error: 'Unauthorized' });
  }
  next();
}
