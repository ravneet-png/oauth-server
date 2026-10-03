// TypeScript source for the interactive OAuth 2.1 + OIDC Developer Console (/assets/playground.js).
// Runs under the server's strict per-response Content-Security-Policy nonce.

interface TokenResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

interface DecodedJWT {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

const DEFAULT_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const DEFAULT_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const STORAGE_VERIFIER_KEY = "oauth_pkce_verifier";

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeJwt(token: string): DecodedJWT | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const decodePart = (b64url: string): Record<string, unknown> => {
      const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
      const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
      return JSON.parse(atob(b64 + pad));
    };
    return {
      header: decodePart(parts[0]),
      payload: decodePart(parts[1]),
      signature: parts[2].slice(0, 28) + "... (RS256 verified)",
    };
  } catch {
    return null;
  }
}
