const API_BASE_URL =
  process.env.NUTRIHELP_API_URL || "http://localhost:80";

/**
 * Fetch the authenticated user's meal plan
 */
export async function getMealPlan(token?: string) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}/api/mealplan`, {
    method: "GET",
    headers,
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}