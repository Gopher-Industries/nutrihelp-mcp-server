import type { AuthenticatedUser } from "./authTypes.js";
import { createSupabaseAuthClient } from "./supabaseClient.js";

/**
 * Validates a Supabase access token and returns the verified user identity.
 */
export async function validateSupabaseToken(
  token: string,
): Promise<AuthenticatedUser> {
  const cleanedToken = token.trim();

  if (!cleanedToken) {
    throw new Error("Supabase access token is required.");
  }

  const supabase = createSupabaseAuthClient();

  const { data, error } = await supabase.auth.getClaims(cleanedToken);

  if (error || !data?.claims) {
    throw new Error("Invalid or expired Supabase access token.");
  }

  const claims = data.claims;

  if (typeof claims.sub !== "string" || !claims.sub) {
    throw new Error("The verified token does not contain a valid user ID.");
  }

  return {
    userId: claims.sub,
    email: typeof claims.email === "string" ? claims.email : undefined,
    expiresAt: typeof claims.exp === "number" ? claims.exp : undefined,
  };
}