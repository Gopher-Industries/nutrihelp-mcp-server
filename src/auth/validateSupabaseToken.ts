import { verify, type JwtPayload } from "jsonwebtoken";
import type { AuthenticatedUser } from "./authTypes.js";

interface NutriHelpTokenPayload extends JwtPayload {
  userId?: number;
  email?: string;
  role?: string;
  type?: string;
}

/**
 * Validates a NutriHelp JWT and returns the authenticated user.
 */
export async function validateSupabaseToken(
  token: string,
): Promise<AuthenticatedUser> {
  const cleanedToken = token.trim();

  if (!cleanedToken) {
    throw new Error("Access token is required.");
  }

  const jwtSecret = process.env.JWT_TOKEN?.trim();
  if (!jwtSecret) {
    throw new Error("JWT_TOKEN is not configured.");
  }

  let decodedToken: string | NutriHelpTokenPayload;

  try {
    decodedToken = verify(cleanedToken, jwtSecret);
  } catch {
    throw new Error("Invalid or expired access token.");
  }

  if (
    typeof decodedToken === "string" ||
    decodedToken.type !== "access" ||
    typeof decodedToken.userId !== "number" ||
    typeof decodedToken.email !== "string" ||
    typeof decodedToken.role !== "string"
  ) {
    throw new Error("The verified token does not contain valid user details.");
  }

  const authenticatedUser: AuthenticatedUser = {
    userId: decodedToken.userId,
    email: decodedToken.email,
    role: decodedToken.role,
  };

  if (typeof decodedToken.exp === "number") {
    authenticatedUser.expiresAt = decodedToken.exp;
  }

  return authenticatedUser;
}