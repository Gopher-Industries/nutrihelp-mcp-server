export interface AuthenticatedUser {
  userId: string;
  email?: string;
  expiresAt?: number;
}