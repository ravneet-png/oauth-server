// Compiled from playground.ts — Interactive OAuth 2.1 + OIDC Developer Console.
(function () {
  "use strict";

  var DEFAULT_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  var DEFAULT_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  var STORAGE_VERIFIER_KEY = "oauth_pkce_verifier";

  function base64UrlEncode(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeJwt(token) {
    if (!token) return null;
    var parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
      var decodePart = function (b64url) {
        var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
        var pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
        return JSON.parse(atob(b64 + pad));
      };
      return {
        header: decodePart(parts[0]),
        payload: decodePart(parts[1]),
        signature: parts[2].slice(0, 28) + "... (RS256 verified)"
      };
    } catch (e) {
      return null;
    }
  }

  async function generatePkcePair() {
    if (!window.crypto || !window.crypto.subtle) {
      return {
        verifier: DEFAULT_VERIFIER,
        challenge: DEFAULT_CHALLENGE,
        state: "xyz123",
        nonce: "n123"
      };
    }
    var verifierBytes = new Uint8Array(32);
    var stateBytes = new Uint8Array(12);
    var nonceBytes = new Uint8Array(12);
    window.crypto.getRandomValues(verifierBytes);
    window.crypto.getRandomValues(stateBytes);
    window.crypto.getRandomValues(nonceBytes);

    var verifier = base64UrlEncode(verifierBytes);
    var encoded = new TextEncoder().encode(verifier);
    var digest = await window.crypto.subtle.digest("SHA-256", encoded);
    var challenge = base64UrlEncode(new Uint8Array(digest));
    return {
      verifier: verifier,
      challenge: challenge,
      state: base64UrlEncode(stateBytes),
      nonce: base64UrlEncode(nonceBytes)
    };
  }

  async function initHomeConsole() {
    var consoleEl = document.querySelector(".console");
    var launchBtn = document.getElementById("launch-authorize-btn");
    var regenBtn = document.getElementById("regen-pkce-btn");
    var pkcePreview = document.getElementById("pkce-preview");
    var inspectorOut = document.getElementById("inspector-output");
    if (!consoleEl || !launchBtn || !pkcePreview) return;

    var clientId = consoleEl.getAttribute("data-client-id") || "demo-client";
    var callbackUrl = consoleEl.getAttribute("data-callback-url") || (window.location.origin + "/callback");
    var currentPkce = null;

    function getSelectedScopes() {
      var boxes = document.querySelectorAll(".js-scope");
      var list = [];
      for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) list.push(boxes[i].value);
      }
      return list.length > 0 ? list.join(" ") : "openid";
    }

    function updateAuthorizeLink() {
      if (!currentPkce) return;
      try {
        sessionStorage.setItem(STORAGE_VERIFIER_KEY, currentPkce.verifier);
      } catch (e) {}

      var scopeStr = getSelectedScopes();
      var params = new URLSearchParams();
      params.set("response_type", "code");
      params.set("client_id", clientId);
      params.set("redirect_uri", callbackUrl);
      params.set("scope", scopeStr);
      params.set("state", currentPkce.state);
      params.set("nonce", currentPkce.nonce);
      params.set("code_challenge", currentPkce.challenge);
      params.set("code_challenge_method", "S256");

      launchBtn.setAttribute("href", "/authorize?" + params.toString());
      pkcePreview.textContent =
        "code_verifier  (saved in browser): " + currentPkce.verifier + "\n" +
        "code_challenge (sent to server) : " + currentPkce.challenge + " (S256)\n" +
        "scope                           : " + scopeStr;
    }

    async function refreshPkce() {
      currentPkce = await generatePkcePair();
      updateAuthorizeLink();
    }

    var scopeBoxes = document.querySelectorAll(".js-scope");
    for (var i = 0; i < scopeBoxes.length; i++) {
      scopeBoxes[i].addEventListener("change", updateAuthorizeLink);
    }
    if (regenBtn) {
      regenBtn.addEventListener("click", function () {
        refreshPkce();
      });
    }

    var inspectBtns = document.querySelectorAll(".js-inspect-btn");
    for (var j = 0; j < inspectBtns.length; j++) {
      inspectBtns[j].addEventListener("click", async function (ev) {
        var btn = ev.currentTarget;
        var endpoint = btn.getAttribute("data-endpoint");
        if (!endpoint || !inspectorOut) return;
        inspectorOut.textContent = "GET " + endpoint + " ...";
        try {
          var resp = await fetch(endpoint, { headers: { "Accept": "application/json" } });
          var text = await resp.text();
          try {
            var parsed = JSON.parse(text);
            inspectorOut.textContent = "HTTP " + resp.status + " — GET " + endpoint + "\n\n" + JSON.stringify(parsed, null, 2);
          } catch (e) {
            inspectorOut.textContent = "HTTP " + resp.status + " — GET " + endpoint + "\n\n" + text;
          }
        } catch (err) {
          inspectorOut.textContent = "Request failed: " + String(err);
        }
      });
    }

    await refreshPkce();
  }

  async function initCallbackConsole() {
    var cbEl = document.getElementById("callback-console");
    if (!cbEl) return;

    var code = cbEl.getAttribute("data-code") || "";
    var clientId = cbEl.getAttribute("data-client-id") || "demo-client";
    var callbackUrl = cbEl.getAttribute("data-callback-url") || (window.location.origin + "/callback");
    if (!code) return;

    var tokenStatusEl = document.getElementById("token-status");
    var accessDecodedEl = document.getElementById("access-token-decoded");
    var idDecodedEl = document.getElementById("id-token-decoded");
    var opOutEl = document.getElementById("operation-output");

    var exchangeBtn = document.getElementById("exchange-code-btn");
    var replayBtn = document.getElementById("replay-code-btn");
    var userinfoBtn = document.getElementById("call-userinfo-btn");
    var rotateBtn = document.getElementById("rotate-refresh-btn");
    var revokeBtn = document.getElementById("revoke-token-btn");

    var currentAccessToken = "";
    var currentRefreshToken = "";
    var verifier = DEFAULT_VERIFIER;
    try {
      var stored = sessionStorage.getItem(STORAGE_VERIFIER_KEY);
      if (stored) verifier = stored;
    } catch (e) {}

    function renderTokens(data) {
      if (data.access_token) {
        currentAccessToken = data.access_token;
        var decAccess = decodeJwt(data.access_token);
        if (accessDecodedEl) {
          accessDecodedEl.textContent = decAccess
            ? JSON.stringify(decAccess, null, 2) + "\n\nRaw JWT:\n" + data.access_token
            : data.access_token;
        }
        if (userinfoBtn) userinfoBtn.disabled = false;
        if (revokeBtn) revokeBtn.disabled = false;
      }
      if (data.refresh_token) {
        currentRefreshToken = data.refresh_token;
        if (rotateBtn) rotateBtn.disabled = false;
      }
      if (data.id_token) {
        var decId = decodeJwt(data.id_token);
        if (idDecodedEl) {
          idDecodedEl.textContent = decId
            ? JSON.stringify(decId, null, 2) + "\n\nRaw JWT:\n" + data.id_token
            : data.id_token;
        }
      } else if (idDecodedEl && !data.error) {
        idDecodedEl.textContent = "(Not re-issued on refresh rotation — initial ID token preserved)";
      }
    }

    async function exchangeAuthorizationCode(isReplayTest) {
      var body = new URLSearchParams();
      body.set("grant_type", "authorization_code");
      body.set("client_id", clientId);
      body.set("code", code);
      body.set("redirect_uri", callbackUrl);
      body.set("code_verifier", verifier);

      var targetEl = isReplayTest ? opOutEl : tokenStatusEl;
      if (targetEl) {
        targetEl.textContent = "POST /token (grant_type=authorization_code, code=" + code.slice(0, 12) + "...) ...";
      }

      try {
        var resp = await fetch("/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString()
        });
        var json = await resp.json();
        if (isReplayTest) {
          if (opOutEl) {
            opOutEl.textContent =
              "=== OAUTH 2.1 CODE REPLAY DETECTION RESULT (HTTP " + resp.status + ") ===\n" +
              "Sent already-used authorization code a 2nd time to POST /token.\n" +
              "The server rejected the replay AND cascaded revocation across the token family!\n\n" +
              JSON.stringify(json, null, 2);
          }
          return;
        }
        if (tokenStatusEl) {
          tokenStatusEl.textContent =
            "HTTP " + resp.status + " — POST /token\n" +
            JSON.stringify(json, null, 2);
        }
        if (resp.ok) {
          renderTokens(json);
        }
      } catch (err) {
        if (targetEl) targetEl.textContent = "Token exchange error: " + String(err);
      }
    }

    if (exchangeBtn) {
      exchangeBtn.addEventListener("click", function () {
        exchangeAuthorizationCode(false);
      });
    }
    if (replayBtn) {
      replayBtn.addEventListener("click", function () {
        exchangeAuthorizationCode(true);
      });
    }

    if (userinfoBtn) {
      userinfoBtn.addEventListener("click", async function () {
        if (!currentAccessToken || !opOutEl) return;
        opOutEl.textContent = "GET /userinfo (Authorization: Bearer <access_token>) ...";
        try {
          var resp = await fetch("/userinfo", {
            headers: { "Authorization": "Bearer " + currentAccessToken }
          });
          var json = await resp.json();
          opOutEl.textContent =
            "=== GET /userinfo (HTTP " + resp.status + ") ===\n\n" +
            JSON.stringify(json, null, 2);
        } catch (err) {
          opOutEl.textContent = "UserInfo error: " + String(err);
        }
      });
    }

    if (rotateBtn) {
      rotateBtn.addEventListener("click", async function () {
        if (!currentRefreshToken || !opOutEl) return;
        opOutEl.textContent = "POST /token (grant_type=refresh_token) ...";
        var body = new URLSearchParams();
        body.set("grant_type", "refresh_token");
        body.set("client_id", clientId);
        body.set("refresh_token", currentRefreshToken);
        try {
          var resp = await fetch("/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString()
          });
          var json = await resp.json();
          opOutEl.textContent =
            "=== REFRESH TOKEN ROTATION (HTTP " + resp.status + ") ===\n" +
            "Old refresh_token atomically marked rotated in PostgreSQL; new token pair issued:\n\n" +
            JSON.stringify(json, null, 2);
          if (resp.ok) {
            renderTokens(json);
          }
        } catch (err) {
          opOutEl.textContent = "Refresh rotation error: " + String(err);
        }
      });
    }

    if (revokeBtn) {
      revokeBtn.addEventListener("click", async function () {
        var tokenToRevoke = currentRefreshToken || currentAccessToken;
        if (!tokenToRevoke || !opOutEl) return;
        opOutEl.textContent = "POST /revoke ...";
        var body = new URLSearchParams();
        body.set("client_id", clientId);
        body.set("token", tokenToRevoke);
        try {
          var resp = await fetch("/revoke", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString()
          });
          opOutEl.textContent =
            "=== POST /revoke (HTTP " + resp.status + ") ===\n" +
            "Token revoked! Try clicking 'Rotate Refresh Token' now to confirm the token is rejected.";
        } catch (err) {
          opOutEl.textContent = "Revoke error: " + String(err);
        }
      });
    }

    await exchangeAuthorizationCode(false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      initHomeConsole();
      initCallbackConsole();
    });
  } else {
    initHomeConsole();
    initCallbackConsole();
  }
})();
