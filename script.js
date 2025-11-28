// -------------------------------
// Données de base
// -------------------------------

// Liste des sites déjà analysés (vient des réponses du LLM)
const sites = [];

// Stocke les conversations par site : { [siteId]: [ { from: 'user'|'agent', text: '...' } ] }
const conversations = {};

// Site courant sélectionné
let currentSiteId = null;

// -------------------------------
// Sélection des éléments du DOM
// -------------------------------
const siteListEl = document.getElementById("site-list");
const currentSiteNameEl = document.getElementById("current-site-name");
const chatMessagesEl = document.getElementById("chat-messages");
const chatFormEl = document.getElementById("chat-form");
const userInputEl = document.getElementById("user-input");

// -------------------------------
// Fonctions d'affichage
// -------------------------------

function renderSiteList() {
  siteListEl.innerHTML = "";

  sites.forEach((site) => {
    const li = document.createElement("li");
    li.className = "site-item";
    li.dataset.id = site.id;

    if (site.id === currentSiteId) {
      li.classList.add("active");
    }

    // Texte du site
    const siteText = document.createElement("span");
    siteText.textContent = site.label;
    li.appendChild(siteText);

    // Bouton de suppression
    const deleteBtn = document.createElement("button");
    deleteBtn.className = "delete-btn";
    deleteBtn.innerHTML = "×";
    deleteBtn.title = "Supprimer ce site";
    deleteBtn.setAttribute("aria-label", "Supprimer");

    // Event listener pour la suppression
    deleteBtn.addEventListener("click", (e) => {
      e.stopPropagation(); // Empêche de sélectionner le site
      deleteSite(site.id, li);
    });

    li.appendChild(deleteBtn);

    // Event listener pour sélectionner le site
    li.addEventListener("click", () => {
      selectSite(site.id);
    });

    siteListEl.appendChild(li);
  });
}

// -------------------------------
// Fonction de suppression d'un site
// -------------------------------
async function deleteSite(siteId, liElement) {
  // Confirmation (optionnelle - vous pouvez retirer si vous voulez)
  const site = sites.find((s) => s.id === siteId);
  const confirmed = confirm(`Voulez-vous vraiment supprimer "${site.label}" ?`);
  
  if (!confirmed) return;

  // Animation de sortie
  liElement.style.opacity = "0";
  liElement.style.transform = "translateX(-10px)";
  liElement.style.transition = "all 0.15s ease";

  try {
    // Appeler l'API pour supprimer le site de la base de données
    const response = await fetch(`http://localhost:8000/api/sites/${siteId}`, {
      method: "DELETE"
    });
    
    if (!response.ok) {
      throw new Error(`Failed to delete site: ${response.status}`);
    }
    
    setTimeout(() => {
      // Supprimer le site du tableau
      const index = sites.findIndex((s) => s.id === siteId);
      if (index !== -1) {
        sites.splice(index, 1);
      }

      // Supprimer la conversation associée
      delete conversations[siteId];

      // Si c'était le site actif, réinitialiser
      if (currentSiteId === siteId) {
        currentSiteId = null;
        currentSiteNameEl.textContent = "Aucun site sélectionné";
        renderConversation();
      }

      // Rafraîchir la liste
      renderSiteList();
    }, 150);
    
  } catch (error) {
    console.error("Error deleting site:", error);
    alert("Erreur lors de la suppression du site");
    // Restaurer l'élément
    liElement.style.opacity = "1";
    liElement.style.transform = "translateX(0)";
  }
}

async function selectSite(siteId) {
  currentSiteId = siteId;
  const site = sites.find((s) => s.id === siteId);

  currentSiteNameEl.textContent = site ? site.label : "Aucun site sélectionné";

  renderSiteList();
  
  // Charger l'historique du site s'il n'est pas déjà chargé
  if (site && (!conversations[siteId] || conversations[siteId].length === 0)) {
    await loadSiteHistory(siteId);
  } else {
    renderConversation();
  }
}

function renderConversation() {
  chatMessagesEl.innerHTML = "";

  if (!currentSiteId) {
    return;
  }

  const msgs = conversations[currentSiteId] || [];

  msgs.forEach((msg) => {
    const row = document.createElement("div");
    row.className = `message-row ${msg.from}`;

    const bubble = document.createElement("div");
    bubble.className = "message-bubble";
    
    // Si c'est un message "typing", ajouter une animation
    if (msg.isTyping) {
      bubble.classList.add("typing");
      bubble.innerHTML = `<span class="typing-dots"><span>.</span><span>.</span><span>.</span></span>`;
    } else {
      // Préserver les retours à la ligne
      bubble.style.whiteSpace = "pre-wrap";
      bubble.textContent = msg.text;
    }

    row.appendChild(bubble);
    chatMessagesEl.appendChild(row);
  });

  // Scroll automatique vers le bas
  chatMessagesEl.scrollTop = chatMessagesEl.scrollHeight;
}

// -------------------------------
// Normalisation de ce que renvoie le LLM pour le site
// -------------------------------
function normalizeSiteFromBackend(siteField) {
  if (!siteField) return null;

  // Cas string
  if (typeof siteField === "string") {
    const raw = siteField.trim();
    if (!raw) return null;

    let url = raw;
    if (!/^https?:\/\//i.test(url)) {
      url = "https://" + url; // on ajoute https si manquant
    }

    const label = url
      .replace(/^https?:\/\//, "")
      .replace(/\/$/, "");

    return { url, label };
  }

  // Cas objet { url, label }
  if (typeof siteField === "object") {
    let url = siteField.url || "";
    if (!/^https?:\/\//i.test(url)) {
      url = "https://" + url;
    }
    const label =
      siteField.label ||
      url.replace(/^https?:\/\//, "").replace(/\/$/, "");

    return { url, label };
  }

  return null;
}

// -------------------------------
// Appel au backend FastAPI
// -------------------------------
async function callAgentAPI(prompt, currentSiteUrl) {
  try {
    const response = await fetch("http://localhost:8000/api/agent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: prompt,
        currentSite: currentSiteUrl
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data; // { site: "...", reply: "...", metadata: {...} }
  } catch (error) {
    console.error("Error calling agent API:", error);
    
    // Fallback en cas d'erreur
    return {
      site: currentSiteUrl,
      reply: `Erreur de connexion au serveur: ${error.message}\n\nAssurez-vous que le serveur FastAPI est démarré avec:\ncd cyber-security\npython -m uvicorn server.main:app --reload`
    };
  }
}

// -------------------------------
// Fonction utilitaire : détection de site locale (backup)
// -------------------------------
function detectSiteLocally(prompt, fallbackUrl) {
  // URL complète
  const fullUrlRegex = /(https?:\/\/[^\s]+)/i;
  const fullMatch = prompt.match(fullUrlRegex);
  if (fullMatch) {
    return fullMatch[0];
  }

  // Domaine type "exemple.com", "site.tn", etc.
  const domainRegex = /\b([a-z0-9-]+\.(com|tn|net|org|io|dev|local|test))\b/i;
  const domainMatch = prompt.match(domainRegex);
  if (domainMatch) {
    return domainMatch[1]; // ex: "facebook.com"
  }

  // Sinon, on garde le site courant si dispo
  if (fallbackUrl) return fallbackUrl;

  return null;
}

// -------------------------------
// Gestion du formulaire de chat
// -------------------------------
chatFormEl.addEventListener("submit", async (event) => {
  event.preventDefault();

  const prompt = userInputEl.value.trim();
  if (!prompt) return;

  const currentSiteUrl =
    currentSiteId != null
      ? (sites.find((s) => s.id === currentSiteId) || {}).url
      : null;

  // Afficher immédiatement le message de l'utilisateur
  if (currentSiteId) {
    // Ajouter le message utilisateur à la conversation actuelle
    if (!conversations[currentSiteId]) {
      conversations[currentSiteId] = [];
    }
    conversations[currentSiteId].push({
      from: "user",
      text: prompt
    });
    renderConversation();
  }

  // Vider l'input immédiatement
  userInputEl.value = "";

  // Ajouter un message "typing indicator"
  const typingMessage = {
    from: "agent",
    text: "Agent en train d'analyser...",
    isTyping: true
  };
  
  if (currentSiteId) {
    conversations[currentSiteId].push(typingMessage);
    renderConversation();
  }

  // Appeler le backend
  let agentData;
  try {
    agentData = await callAgentAPI(prompt, currentSiteUrl);
  } catch (err) {
    console.error(err);
    
    // Retirer le typing indicator
    if (currentSiteId && conversations[currentSiteId]) {
      const typingIndex = conversations[currentSiteId].findIndex(m => m.isTyping);
      if (typingIndex !== -1) {
        conversations[currentSiteId].splice(typingIndex, 1);
      }
      
      // Ajouter message d'erreur
      conversations[currentSiteId].push({
        from: "agent",
        text: "Erreur lors de l'appel à l'agent. Vérifiez que le serveur est démarré."
      });
      renderConversation();
    }
    return;
  }

  // Retirer le typing indicator
  if (currentSiteId && conversations[currentSiteId]) {
    const typingIndex = conversations[currentSiteId].findIndex(m => m.isTyping);
    if (typingIndex !== -1) {
      conversations[currentSiteId].splice(typingIndex, 1);
    }
  }

  // Recharger la liste des sites depuis le backend
  await loadSitesFromBackend();

  // Si un site a été détecté/créé, le sélectionner et charger l'historique complet
  if (agentData.site) {
    const siteInfo = normalizeSiteFromBackend(agentData.site);
    if (siteInfo) {
      // Trouver le site dans la liste rechargée
      const site = sites.find((s) => s.url === siteInfo.url);
      if (site) {
        // Sélectionner ce site et recharger son historique depuis la BDD
        currentSiteId = site.id;
        currentSiteNameEl.textContent = site.label;
        renderSiteList();
        await loadSiteHistory(site.id);
      }
    }
  } else if (currentSiteId) {
    // Pas de nouveau site, juste recharger l'historique du site actuel
    await loadSiteHistory(currentSiteId);
  }
});

// -------------------------------
// Chargement des sites depuis le backend
// -------------------------------
async function loadSitesFromBackend() {
  try {
    const response = await fetch("http://localhost:8000/api/sites");
    
    if (!response.ok) {
      console.error("Failed to load sites:", response.status);
      return;
    }
    
    const data = await response.json();
    
    // Vider les sites existants
    sites.length = 0;
    
    // Charger les sites depuis la base de données
    data.sites.forEach((siteData) => {
      const site = {
        id: siteData.id,
        url: siteData.url,
        label: siteData.label
      };
      sites.push(site);
      
      // Initialiser la conversation vide (sera chargée à la sélection)
      if (!conversations[site.id]) {
        conversations[site.id] = [];
      }
    });
    
    renderSiteList();
    
  } catch (error) {
    console.error("Error loading sites:", error);
    // Ne pas afficher d'alerte, juste logger l'erreur
  }
}

// -------------------------------
// Charger l'historique d'un site
// -------------------------------
async function loadSiteHistory(siteId) {
  try {
    const response = await fetch(`http://localhost:8000/api/sites/${siteId}/history`);
    
    if (!response.ok) {
      console.error("Failed to load site history:", response.status);
      return;
    }
    
    const data = await response.json();
    
    // Charger les messages de conversation
    conversations[siteId] = data.conversation.map((msg) => ({
      from: msg.role === "user" ? "user" : "agent",
      text: msg.content
    }));
    
    renderConversation();
    
  } catch (error) {
    console.error("Error loading site history:", error);
  }
}

// -------------------------------
// Initialisation
// -------------------------------
(async function init() {
  // Charger les sites depuis le backend
  await loadSitesFromBackend();
  
  renderSiteList();
  renderConversation();
})();