function getSecretIdFromPath() {
  const parts = window.location.pathname.split("/").filter(Boolean);
  if (parts[0] === "view" && parts[1]) {
    return parts[1];
  }
  return null;
}

function isValidPin(pin) {
  return /^\d{6}$/.test(pin);
}

function showBox(element, html, type = "info") {
  element.classList.remove("hidden", "success", "error", "warning");
  element.classList.add(type);
  element.innerHTML = html;
}

// 🔥 amélioration copie (avec feedback)
async function copyText(value, button = null, successLabel = "Copié !") {
  try {
    await navigator.clipboard.writeText(value);

    if (button) {
      const originalText = button.textContent;
      button.textContent = successLabel;
      button.disabled = true;

      setTimeout(() => {
        button.textContent = originalText;
        button.disabled = false;
      }, 1500);
    }
  } catch (error) {
    alert("Impossible de copier.");
  }
}

async function createSecret() {
  const secretInput = document.getElementById("secretInput");
  const pinInput = document.getElementById("pinInput");
  const expirationSelect = document.getElementById("expirationSelect");
  const result = document.getElementById("createResult");

  const secret = secretInput.value.trim();
  const pin = pinInput.value.trim();
  const expiresInMinutes = expirationSelect.value;

  if (!secret) {
    showBox(result, "Erreur : le secret est obligatoire.", "error");
    return;
  }

  if (!isValidPin(pin)) {
    showBox(result, "Erreur : le PIN doit contenir exactement 6 chiffres.", "error");
    return;
  }

  try {
    const response = await fetch("/api/secret", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        secret,
        pin,
        expiresInMinutes
      })
    });

    const data = await response.json();

    if (!response.ok) {
      showBox(result, `Erreur : ${data.error || "création impossible."}`, "error");
      return;
    }

    const fullLink = `${window.location.origin}/view/${data.id}`;

    showBox(
      result,
      `
        <div class="result-title success-text">Lien créé.</div>

        <div class="result-label">Lien sécurisé :</div>
        <div class="code-box">${fullLink}</div>

        <div class="result-label">PIN :</div>
        <div class="code-box">${pin}</div>

        <button class="secondary-btn" onclick="copyText('${fullLink}', this, 'Lien copié !')">Copier le lien</button>
        <button class="secondary-btn" onclick="copyText('${pin}', this, 'PIN copié !')">Copier le PIN</button>

        <p class="result-note">Envoie le lien et le PIN par deux canaux différents si possible.</p>
      `,
      "success"
    );

    // reset inputs
    secretInput.value = "";
    pinInput.value = "";
  } catch (error) {
    showBox(result, "Erreur : impossible de contacter le serveur.", "error");
  }
}

async function readSecret(secretId) {
  const pinInput = document.getElementById("readPinInput");
  const result = document.getElementById("readResult");
  const pin = pinInput.value.trim();

  if (!isValidPin(pin)) {
    showBox(result, "Erreur : le PIN doit contenir exactement 6 chiffres.", "error");
    return;
  }

  try {
    const response = await fetch(`/api/secret/${secretId}/read`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ pin })
    });

    const data = await response.json();

    if (!response.ok) {
      showBox(result, `Erreur : ${data.error || "lecture impossible."}`, "error");
      return;
    }

    showBox(
      result,
      `
        <div class="result-title success-text">Secret déchiffré :</div>
        <div class="secret-box">${data.secret}</div>
        <p class="result-note">Ce secret a maintenant été consommé.</p>
      `,
      "success"
    );

    // reset PIN input
    pinInput.value = "";
  } catch (error) {
    showBox(result, "Erreur : impossible de contacter le serveur.", "error");
  }
}

function init() {
  const secretId = getSecretIdFromPath();

  const createView = document.getElementById("createView");
  const readView = document.getElementById("readView");

  if (secretId) {
    createView.classList.add("hidden");
    readView.classList.remove("hidden");

    document.getElementById("readBtn").addEventListener("click", () => {
      readSecret(secretId);
    });
  } else {
    createView.classList.remove("hidden");
    readView.classList.add("hidden");

    document.getElementById("createBtn").addEventListener("click", createSecret);
  }
}

init();