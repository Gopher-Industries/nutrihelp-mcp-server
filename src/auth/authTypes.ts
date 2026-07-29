export interface AuthenticatedUser {
  userId: number;
  email: string;
  role: string;
  expiresAt?: number;
}