// Browser-side demo for the OAuth console, callback inspector, and account recovery pages.
// Client secrets are accepted only for one request and are never written to browser storage.
(function () {
  "use strict";

  var TRANSACTION_STORAGE_KEY = "oauth_playground_transaction";
  var MAX_TRANSACTION_AGE_MS = 10 * 60 * 1000;

  function base64UrlEncode(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64Basic(value) {
    var bytes = new TextEncoder().encode(value);
    var binary = "";
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function decodeJwt(token) {
    if (!token) return null;
    var parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
      var decodePart = function (segment) {
        var base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
        var padding = base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
        var binary = window.atob(base64 + padding);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        var parsed = JSON.parse(new TextDecoder().decode(bytes));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
        return parsed;
      };
      var header = decodePart(parts[0]);
      var payload = decodePart(parts[1]);
      if (!header || !payload) return null;
      return { header: header, payload: payload };
    } catch (e) {
      return null;
    }
  }

  async function readJSONResponse(response) {
    var text = await response.text();
    if (!text) return {};
    try {
      return JSON.parse(text);
    } catch (e) {
      return { response_text: text };
    }
  }

  function formatHTTPResponse(label, response, json) {
    return "HTTP " + response.status + " — " + label + "\n\n" + JSON.stringify(json, null, 2);
  }

  function setAlert(element, message, kind) {
    if (!element) return;
    element.className = "alert " + (kind === "error" ? "alert--error" : "alert--info");
    element.textContent = message;
    element.hidden = false;
  }

  function safeRemoveTransaction() {
    try {
      window.sessionStorage.removeItem(TRANSACTION_STORAGE_KEY);
    } catch (e) {
      // Storage may be unavailable in a privacy-restricted browser.
    }
  }

  async function generatePKCEPair() {
    if (!window.crypto || !window.crypto.subtle || !window.TextEncoder) {
      throw new Error("Secure WebCrypto is unavailable. Open this page over HTTPS or localhost to start a PKCE flow.");
    }
    var verifierBytes = new Uint8Array(32);
    var stateBytes = new Uint8Array(24);
    var nonceBytes = new Uint8Array(24);
    window.crypto.getRandomValues(verifierBytes);
    window.crypto.getRandomValues(stateBytes);
    window.crypto.getRandomValues(nonceBytes);

    var verifier = base64UrlEncode(verifierBytes);
    var digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return {
      verifier: verifier,
      challenge: base64UrlEncode(new Uint8Array(digest)),
      state: base64UrlEncode(stateBytes),
      nonce: base64UrlEncode(nonceBytes)
    };
  }

  function initHomeConsole() {
    var root = document.getElementById("developer-console");
    if (!root) return;

    var launchButton = document.getElementById("launch-authorize-btn");
    var refreshButton = document.getElementById("regen-pkce-btn");
    var preview = document.getElementById("pkce-preview");
    var flowStatus = document.getElementById("flow-status");
    var clientID = root.getAttribute("data-client-id") || "";
    var issuer = root.getAttribute("data-issuer") || "";
    var callbackURL = root.getAttribute("data-callback-url") || "";
    var parEndpoint = root.getAttribute("data-par-endpoint") || "/par";
    var currentPair = null;

    function selectedScopes() {
      var boxes = document.querySelectorAll(".js-scope");
      var result = [];
      for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) result.push(boxes[i].value);
      }
      return result.join(" ");
    }

    function updatePreview() {
      if (!preview || !currentPair) return;
      var scope = selectedScopes();
      preview.textContent =
        "code_verifier  (tab-scoped): " + currentPair.verifier + "\n" +
        "code_challenge (S256):       " + currentPair.challenge + "\n" +
        "scope: " + (scope || "(none)");
    }

    async function refreshPair() {
      if (launchButton) launchButton.disabled = true;
      if (preview) preview.textContent = "Generating a cryptographically random PKCE pair…";
      if (flowStatus) flowStatus.textContent = "";
      safeRemoveTransaction();
      try {
        currentPair = await generatePKCEPair();
        updatePreview();
        if (launchButton) launchButton.disabled = false;
      } catch (error) {
        currentPair = null;
        if (preview) preview.textContent = String(error.message || error);
        if (flowStatus) flowStatus.textContent = "The authorization flow is unavailable until secure WebCrypto works.";
      }
    }

    function authorizationParameters(pair) {
      var params = new URLSearchParams();
      params.set("response_type", "code");
      params.set("client_id", clientID);
      params.set("redirect_uri", callbackURL);
      var scope = selectedScopes();
      if (scope) params.set("scope", scope);
      params.set("state", pair.state);
      params.set("nonce", pair.nonce);
      params.set("code_challenge", pair.challenge);
      params.set("code_challenge_method", "S256");
      return params;
    }

    async function startAuthorization() {
      if (!currentPair || !launchButton) return;
      launchButton.disabled = true;
      if (flowStatus) flowStatus.textContent = "Preparing a single-use authorization transaction…";

      var transaction = {
        verifier: currentPair.verifier,
        state: currentPair.state,
        nonce: currentPair.nonce,
        issuer: issuer,
        callbackURL: callbackURL,
        clientID: clientID,
        createdAt: Date.now()
      };
      try {
        // Only the PKCE transaction is retained across the redirect. Confidential
        // client credentials are never stored in sessionStorage or localStorage.
        window.sessionStorage.setItem(TRANSACTION_STORAGE_KEY, JSON.stringify(transaction));
      } catch (error) {
        launchButton.disabled = false;
        if (flowStatus) flowStatus.textContent = "This browser blocked session storage; the flow was not started.";
        return;
      }

      try {
        var params = authorizationParameters(currentPair);
        var usePAR = document.getElementById("use-par");
        if (usePAR && usePAR.checked) {
          if (flowStatus) flowStatus.textContent = "Pushing validated parameters to POST /par…";
          var response = await window.fetch(parEndpoint, {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params.toString()
          });
          var json = await readJSONResponse(response);
          if (!response.ok || typeof json.request_uri !== "string" ||
              json.request_uri.indexOf("urn:ietf:params:oauth:request_uri:") !== 0) {
            throw new Error((json.error_description || json.error || "The PAR request was rejected") + " (HTTP " + response.status + ")");
          }
          var pushed = new URLSearchParams();
          pushed.set("client_id", clientID);
          pushed.set("request_uri", json.request_uri);
          if (flowStatus) flowStatus.textContent = "PAR accepted. Redirecting with the one-time request_uri…";
          window.location.assign("/authorize?" + pushed.toString());
          return;
        }

        if (flowStatus) flowStatus.textContent = "Redirecting to the authorization endpoint…";
        window.location.assign("/authorize?" + params.toString());
      } catch (error) {
        safeRemoveTransaction();
        launchButton.disabled = false;
        if (flowStatus) flowStatus.textContent = "Could not start the flow: " + String(error.message || error);
      }
    }

    if (launchButton) launchButton.addEventListener("click", startAuthorization);
    if (refreshButton) refreshButton.addEventListener("click", refreshPair);
    var scopeBoxes = document.querySelectorAll(".js-scope");
    for (var i = 0; i < scopeBoxes.length; i++) {
      scopeBoxes[i].addEventListener("change", updatePreview);
    }

    var inspectButtons = document.querySelectorAll(".js-inspect-btn");
    var inspectorOutput = document.getElementById("inspector-output");
    for (var j = 0; j < inspectButtons.length; j++) {
      inspectButtons[j].addEventListener("click", async function (event) {
        var button = event.currentTarget;
        var endpoint = button.getAttribute("data-endpoint");
        if (!endpoint || !inspectorOutput) return;
        inspectorOutput.textContent = "GET " + endpoint + "…";
        try {
          var response = await window.fetch(endpoint, {
            credentials: "omit",
            headers: { "Accept": "application/json" }
          });
          var json = await readJSONResponse(response);
          inspectorOutput.textContent = formatHTTPResponse("GET " + endpoint, response, json);
        } catch (error) {
          inspectorOutput.textContent = "Request failed: " + String(error);
        }
      });
    }

    initClientCredentials();
    refreshPair();
  }

  function initClientCredentials() {
    var button = document.getElementById("client-credentials-btn");
    if (!button) return;
    var clientIDInput = document.getElementById("client-credentials-id");
    var secretInput = document.getElementById("client-credentials-secret");
    var scopeInput = document.getElementById("client-credentials-scope");
    var output = document.getElementById("client-credentials-output");

    button.addEventListener("click", async function () {
      var clientID = clientIDInput ? clientIDInput.value.trim() : "";
      var clientSecret = secretInput ? secretInput.value : "";
      var scope = scopeInput ? scopeInput.value.trim() : "";
      if (secretInput) secretInput.value = "";
      if (clientIDInput) clientIDInput.value = "";
      if (!clientID || !clientSecret) {
        clientSecret = "";
        if (output) output.textContent = "Enter a confidential client ID and secret for this one request.";
        return;
      }

      button.disabled = true;
      if (output) output.textContent = "POST /token (grant_type=client_credentials)…";
      var authorization = "";
      try {
        authorization = "Basic " + base64Basic(clientID + ":" + clientSecret);
        clientSecret = "";
        var body = new URLSearchParams();
        body.set("grant_type", "client_credentials");
        if (scope) body.set("scope", scope);
        var response = await window.fetch("/token", {
          method: "POST",
          credentials: "omit",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": authorization
          },
          body: body.toString()
        });
        var json = await readJSONResponse(response);
        if (output) output.textContent = formatHTTPResponse("POST /token (client_credentials)", response, json);
      } catch (error) {
        if (output) output.textContent = "Client-credentials request failed: " + String(error);
      } finally {
        // Clear all references we control. No secret is displayed, logged, or persisted.
        clientSecret = "";
        authorization = "";
        if (secretInput) secretInput.value = "";
        if (clientIDInput) clientIDInput.value = "";
        button.disabled = false;
      }
    });
  }

  function initCallbackConsole() {
    var root = document.getElementById("callback-console");
    if (!root) return;

    var status = document.getElementById("callback-validation");
    var errorPanel = document.getElementById("authorization-error");
    var codePanel = document.getElementById("authorization-code-panel");
    var claimsGrid = document.getElementById("token-claims-grid");
    var operationsPanel = document.getElementById("token-operations-panel");
    var noResponsePanel = document.getElementById("no-response-panel");
    var code = root.getAttribute("data-code") || "";
    var returnedState = root.getAttribute("data-state") || "";
    var returnedIssuer = root.getAttribute("data-iss") || "";
    var responseError = root.getAttribute("data-error") || "";
    var expectedIssuer = root.getAttribute("data-issuer") || "";
    var callbackURL = root.getAttribute("data-callback-url") || "";
    var clientID = root.getAttribute("data-client-id") || "";
    var codePresent = root.getAttribute("data-code-present") === "true";
    var statePresent = root.getAttribute("data-state-present") === "true";
    var issuerPresent = root.getAttribute("data-iss-present") === "true";
    var errorPresent = root.getAttribute("data-error-present") === "true";
    var responseValid = root.getAttribute("data-response-valid") === "true";
    var verifier = "";
    var exchangeReady = false;
    var currentAccessToken = "";
    var currentRefreshToken = "";

    function rejectCallback(message) {
      setAlert(status, message, "error");
      if (codePanel) codePanel.hidden = true;
      if (errorPanel) errorPanel.hidden = true;
      if (noResponsePanel) noResponsePanel.hidden = true;
    }

    function validateCallback() {
      if (!responseValid) {
        rejectCallback("The authorization response is malformed or contains duplicate parameters. No token exchange was allowed.");
        return;
      }
      if (!codePresent && !errorPresent) {
        setAlert(status, "No authorization response was found. Start a new flow from the Developer Console.", "info");
        if (noResponsePanel) noResponsePanel.hidden = false;
        return;
      }
      if (codePresent && errorPresent) {
        rejectCallback("The response contains both a code and an error. No token exchange was allowed.");
        return;
      }
      if (!statePresent || !issuerPresent) {
        rejectCallback("The response is missing state or issuer. No token exchange was allowed.");
        return;
      }

      var transaction;
      try {
        transaction = JSON.parse(window.sessionStorage.getItem(TRANSACTION_STORAGE_KEY) || "null");
      } catch (error) {
        transaction = null;
      }
      if (!transaction || typeof transaction !== "object") {
        rejectCallback("No pending PKCE transaction is available in this tab. Restart from the Developer Console.");
        return;
      }
      if (typeof transaction.createdAt !== "number" || Date.now() - transaction.createdAt > MAX_TRANSACTION_AGE_MS) {
        rejectCallback("The pending authorization transaction has expired. Start a new flow.");
        return;
      }
      if (transaction.state !== returnedState) {
        rejectCallback("The returned state does not match this tab’s pending transaction. No token exchange was allowed.");
        return;
      }
      if (transaction.issuer !== expectedIssuer || returnedIssuer !== expectedIssuer) {
        rejectCallback("The returned issuer does not exactly match the expected issuer. No token exchange was allowed.");
        return;
      }
      if (transaction.callbackURL !== callbackURL || transaction.clientID !== clientID ||
          typeof transaction.verifier !== "string" || transaction.verifier.length < 43) {
        rejectCallback("The pending PKCE transaction does not match this callback. No token exchange was allowed.");
        return;
      }
      if (codePresent && !code) {
        rejectCallback("The authorization code is empty. No token exchange was allowed.");
        return;
      }

      // Consume the local state before exposing any action. This prevents a callback
      // refresh from replaying the same authorization response.
      safeRemoveTransaction();
      if (errorPresent) {
        setAlert(status, "State and issuer match. The authorization server returned an error.", "info");
        if (errorPanel) {
          if (!responseError) errorPanel.textContent = "Authorization error";
          errorPanel.hidden = false;
        }
        return;
      }

      verifier = transaction.verifier;
      exchangeReady = true;
      setAlert(status, "State matches and the issuer is exact. The one-time code is ready for a PKCE exchange.", "info");
      if (codePanel) codePanel.hidden = false;
      var exchangeButton = document.getElementById("exchange-code-btn");
      var replayButton = document.getElementById("replay-code-btn");
      if (exchangeButton) exchangeButton.disabled = false;
      if (replayButton) replayButton.disabled = false;
    }

    var tokenStatus = document.getElementById("token-status");
    var accessDecoded = document.getElementById("access-token-decoded");
    var idDecoded = document.getElementById("id-token-decoded");
    var operationOutput = document.getElementById("operation-output");
    var exchangeButton = document.getElementById("exchange-code-btn");
    var replayButton = document.getElementById("replay-code-btn");
    var userinfoButton = document.getElementById("call-userinfo-btn");
    var introspectButton = document.getElementById("call-introspect-btn");
    var refreshButton = document.getElementById("rotate-refresh-btn");
    var revokeButton = document.getElementById("revoke-token-btn");

    function renderTokens(data) {
      if (data.access_token) {
        currentAccessToken = data.access_token;
        var decodedAccess = decodeJwt(data.access_token);
        if (accessDecoded) {
          accessDecoded.textContent = decodedAccess
            ? "Decoded only — signature and claims are not verified here.\n\n" + JSON.stringify(decodedAccess, null, 2) + "\n\nRaw access token (sensitive):\n" + data.access_token
            : "Could not decode this token as a JWT.\n\nRaw access token (sensitive):\n" + data.access_token;
        }
        if (userinfoButton) userinfoButton.disabled = false;
        if (introspectButton) introspectButton.disabled = false;
        if (revokeButton) revokeButton.disabled = false;
      }
      if (data.refresh_token) {
        currentRefreshToken = data.refresh_token;
        if (refreshButton) refreshButton.disabled = false;
      }
      if (data.id_token) {
        var decodedID = decodeJwt(data.id_token);
        if (idDecoded) {
          idDecoded.textContent = decodedID
            ? "Decoded only — signature and claims are not verified here.\n\n" + JSON.stringify(decodedID, null, 2) + "\n\nRaw ID token (sensitive):\n" + data.id_token
            : "Could not decode this token as a JWT.\n\nRaw ID token (sensitive):\n" + data.id_token;
        }
      } else if (idDecoded && !data.error) {
        idDecoded.textContent = "No ID token was returned for this response.";
      }
      if (claimsGrid) claimsGrid.hidden = false;
      if (operationsPanel) operationsPanel.hidden = false;
    }

    async function exchangeAuthorizationCode(isReplayTest) {
      if (!exchangeReady || !verifier || !code) return;
      var target = isReplayTest ? operationOutput : tokenStatus;
      if (target) target.textContent = "POST /token (grant_type=authorization_code)…";
      if (!isReplayTest && exchangeButton) exchangeButton.disabled = true;
      if (isReplayTest && replayButton) replayButton.disabled = true;

      var body = new URLSearchParams();
      body.set("grant_type", "authorization_code");
      body.set("client_id", clientID);
      body.set("code", code);
      body.set("redirect_uri", callbackURL);
      body.set("code_verifier", verifier);
      try {
        var response = await window.fetch("/token", {
          method: "POST",
          credentials: "omit",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString()
        });
        var json = await readJSONResponse(response);
        if (isReplayTest) {
          if (operationOutput) {
            operationOutput.textContent = formatHTTPResponse("authorization-code replay test", response, json) +
              "\n\nA used code should be rejected. Depending on the token-family state, replay detection may revoke tokens in that family.";
          }
          return;
        }
        if (tokenStatus) tokenStatus.textContent = formatHTTPResponse("POST /token", response, json);
        if (response.ok) {
          renderTokens(json);
        } else if (exchangeButton) {
          exchangeButton.disabled = false;
        }
      } catch (error) {
        if (target) target.textContent = "Token exchange failed: " + String(error);
        if (!isReplayTest && exchangeButton) exchangeButton.disabled = false;
      } finally {
        if (isReplayTest && replayButton) replayButton.disabled = false;
      }
    }

    if (exchangeButton) exchangeButton.addEventListener("click", function () { exchangeAuthorizationCode(false); });
    if (replayButton) replayButton.addEventListener("click", function () { exchangeAuthorizationCode(true); });

    if (userinfoButton) {
      userinfoButton.addEventListener("click", async function () {
        if (!currentAccessToken || !operationOutput) return;
        operationOutput.textContent = "GET /userinfo (Bearer access token)…";
        try {
          var response = await window.fetch("/userinfo", {
            credentials: "omit",
            headers: { "Authorization": "Bearer " + currentAccessToken }
          });
          var json = await readJSONResponse(response);
          operationOutput.textContent = formatHTTPResponse("GET /userinfo", response, json);
        } catch (error) {
          operationOutput.textContent = "Userinfo request failed: " + String(error);
        }
      });
    }

    if (introspectButton) {
      introspectButton.addEventListener("click", async function () {
        if (!currentAccessToken || !operationOutput) return;
        operationOutput.textContent = "POST /introspect…";
        var body = new URLSearchParams();
        body.set("client_id", clientID);
        body.set("token", currentAccessToken);
        try {
          // demo-client is a public client, so it authenticates with client_id only.
          // The server still checks that the introspected token belongs to this client.
          var response = await window.fetch("/introspect", {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString()
          });
          var json = await readJSONResponse(response);
          operationOutput.textContent = formatHTTPResponse("POST /introspect", response, json);
        } catch (error) {
          operationOutput.textContent = "Introspection request failed: " + String(error);
        }
      });
    }

    if (refreshButton) {
      refreshButton.addEventListener("click", async function () {
        if (!currentRefreshToken || !operationOutput) return;
        operationOutput.textContent = "POST /token (grant_type=refresh_token)…";
        var body = new URLSearchParams();
        body.set("grant_type", "refresh_token");
        body.set("client_id", clientID);
        body.set("refresh_token", currentRefreshToken);
        try {
          var response = await window.fetch("/token", {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString()
          });
          var json = await readJSONResponse(response);
          operationOutput.textContent = formatHTTPResponse("POST /token (refresh_token)", response, json);
          if (response.ok) renderTokens(json);
        } catch (error) {
          operationOutput.textContent = "Refresh request failed: " + String(error);
        }
      });
    }

    if (revokeButton) {
      revokeButton.addEventListener("click", async function () {
        var token = currentRefreshToken || currentAccessToken;
        if (!token || !operationOutput) return;
        operationOutput.textContent = "POST /revoke…";
        var body = new URLSearchParams();
        body.set("client_id", clientID);
        body.set("token", token);
        try {
          var response = await window.fetch("/revoke", {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString()
          });
          var json = await readJSONResponse(response);
          operationOutput.textContent = formatHTTPResponse("POST /revoke", response, json);
        } catch (error) {
          operationOutput.textContent = "Revocation request failed: " + String(error);
        }
      });
    }

    validateCallback();
  }

  function initRecoveryForms() {
    var forgotForm = document.getElementById("forgot-password-form");
    if (forgotForm) {
      var emailInput = document.getElementById("forgot-password-email");
      var forgotStatus = document.getElementById("forgot-password-status");
      var forgotButton = document.getElementById("forgot-password-submit");
      forgotForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        var email = emailInput ? emailInput.value.trim() : "";
        if (!emailInput || !emailInput.validity.valid) {
          setAlert(forgotStatus, "Enter a valid email address and try again.", "error");
          return;
        }
        if (forgotButton) forgotButton.disabled = true;
        setAlert(forgotStatus, "Sending the request…", "info");
        try {
          var response = await window.fetch("/forgot-password", {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ email: email })
          });
          if (response.status === 202) {
            // Keep the same success text for every address to avoid account enumeration.
            setAlert(forgotStatus, "If that address has an account, a reset link is on its way. Check your inbox and spam folder.", "info");
            if (emailInput) emailInput.value = "";
          } else {
            setAlert(forgotStatus, "The request could not be completed right now. Please try again later.", "error");
          }
        } catch (error) {
          setAlert(forgotStatus, "The request could not be completed right now. Please try again later.", "error");
        } finally {
          if (forgotButton) forgotButton.disabled = false;
        }
      });
    }

    var resetPage = document.getElementById("password-reset-page");
    if (!resetPage) return;
    var resetToken = resetPage.getAttribute("data-reset-token") || "";
    var passwordInput = document.getElementById("password-reset-password");
    var confirmInput = document.getElementById("password-reset-confirm");
    var resetForm = document.getElementById("password-reset-form");
    var resetStatus = document.getElementById("password-reset-status");
    var resetButton = document.getElementById("password-reset-submit");
    var minimumLength = Number(resetPage.getAttribute("data-min-password-length")) || 8;

    // The URL contained a one-time bearer token. Remove it from browser history as soon
    // as the page script has captured it; the token is kept only in this closure.
    resetPage.removeAttribute("data-reset-token");
    try {
      window.history.replaceState(null, document.title, window.location.pathname);
    } catch (error) {
      // The page remains usable if history rewriting is unavailable.
    }

    if (!resetToken) {
      if (resetForm) resetForm.hidden = true;
      setAlert(resetStatus, "This reset link is missing or malformed. Request a new link to continue.", "error");
      return;
    }

    if (resetForm) {
      resetForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        var password = passwordInput ? passwordInput.value : "";
        var confirmation = confirmInput ? confirmInput.value : "";
        if (password.length < minimumLength) {
          setAlert(resetStatus, "Choose a password with at least " + minimumLength + " characters.", "error");
          return;
        }
        if (password !== confirmation) {
          setAlert(resetStatus, "The passwords do not match.", "error");
          return;
        }

        if (resetButton) resetButton.disabled = true;
        setAlert(resetStatus, "Updating your password…", "info");
        try {
          var response = await window.fetch("/reset-password", {
            method: "POST",
            credentials: "omit",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ token: resetToken, password: password })
          });
          var json = await readJSONResponse(response);
          if (response.ok) {
            resetToken = "";
            if (resetForm) resetForm.hidden = true;
            setAlert(resetStatus, "Your password has been updated. You can now sign in.", "info");
          } else if (response.status === 401 && json.error === "invalid_token") {
            resetToken = "";
            if (resetForm) resetForm.hidden = true;
            setAlert(resetStatus, "This reset link is invalid, expired, or already used. Request a new link to continue.", "error");
          } else if (json.error === "invalid_request") {
            setAlert(resetStatus, json.error_description || "The new password was not accepted. Check the minimum length and try again.", "error");
          } else {
            setAlert(resetStatus, "The password could not be updated right now. Please try again later.", "error");
          }
        } catch (error) {
          setAlert(resetStatus, "The password could not be updated right now. Please try again later.", "error");
        } finally {
          if (passwordInput) passwordInput.value = "";
          if (confirmInput) confirmInput.value = "";
          if (resetButton) resetButton.disabled = false;
        }
      });
    }
  }

  function boot() {
    initHomeConsole();
    initCallbackConsole();
    initRecoveryForms();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
