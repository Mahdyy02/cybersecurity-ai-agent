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
const newWebsiteBtn = document.getElementById("new-website-btn");
const appLogo = document.getElementById("app-logo");

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

  msgs.forEach((msg, index) => {
    const row = document.createElement("div");
    row.className = `message-row ${msg.from}`;

    const bubble = document.createElement("div");
    bubble.className = "message-bubble";
    
    // Si c'est un message "typing", ajouter une animation
    if (msg.isTyping) {
      bubble.classList.add("typing");
      bubble.innerHTML = `<span class="typing-dots"><span>.</span><span>.</span><span>.</span></span>`;
    } else if (msg.isProcess) {
      // Affichage spécial pour les process/commandes
      bubble.classList.add("process-message");
      bubble.innerHTML = `<div class="process-header">⚙️ Agent Process</div><pre class="process-content">${escapeHtml(msg.text)}</pre>`;
    } else {
      // Convertir le Markdown en HTML pour les messages de l'agent
      if (msg.from === "agent") {
        bubble.innerHTML = formatMarkdown(msg.text);
      } else {
        // Messages utilisateur : préserver les retours à la ligne
        bubble.style.whiteSpace = "pre-wrap";
        bubble.textContent = msg.text;
      }
    }

    // Animation d'entrée progressive
    bubble.style.opacity = "0";
    bubble.style.transform = "translateY(10px)";
    
    row.appendChild(bubble);
    chatMessagesEl.appendChild(row);
    
    // Déclencher l'animation
    setTimeout(() => {
      bubble.style.transition = "all 0.3s ease";
      bubble.style.opacity = "1";
      bubble.style.transform = "translateY(0)";
    }, index * 50);
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
// Fonction utilitaire pour échapper le HTML
// -------------------------------
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// -------------------------------
// Fonction pour formater le Markdown en HTML
// -------------------------------
function formatMarkdown(text) {
  let html = escapeHtml(text);
  
  // Gras: **texte** ou __texte__
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/__(.+?)__/g, '<strong>$1</strong>');
  
  // Italique: *texte* ou _texte_
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  html = html.replace(/_(.+?)_/g, '<em>$1</em>');
  
  // Code inline: `code`
  html = html.replace(/`(.+?)`/g, '<code class="inline-code">$1</code>');
  
  // Liens: [texte](url)
  html = html.replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  
  // Titres: ### Titre
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  
  // Listes à puces: - item ou * item ou • item
  html = html.replace(/^[•\-\*] (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
  
  // Listes numérotées: 1. item
  html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
  
  // Emojis avec texte (comme 🚨 Critical Issues:)
  html = html.replace(/^([🔍🚨💡📊⚠️✅✓⚙️📝🎯💉📍🔒]+)\s*\*\*(.+?)\*\*:?/gm, '<div class="emoji-header">$1 <strong>$2</strong></div>');
  
  // Retours à la ligne
  html = html.replace(/\n\n/g, '</p><p>');
  html = html.replace(/\n/g, '<br>');
  
  // Envelopper dans un paragraphe
  html = '<p>' + html + '</p>';
  
  // Nettoyer les paragraphes vides
  html = html.replace(/<p><\/p>/g, '');
  html = html.replace(/<p><br><\/p>/g, '');
  
  return html;
}

// -------------------------------
// Gestion du formulaire de chat
// -------------------------------

// Gestion de la touche Entrée dans le textarea
userInputEl.addEventListener("keydown", (event) => {
  // Si Entrée est pressée sans Shift
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    chatFormEl.dispatchEvent(new Event("submit"));
  }
});

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

  // Si un site a été détecté/créé, le sélectionner
  let targetSiteId = currentSiteId;
  if (agentData.site) {
    const siteInfo = normalizeSiteFromBackend(agentData.site);
    if (siteInfo) {
      // Trouver le site dans la liste rechargée
      const site = sites.find((s) => s.url === siteInfo.url);
      if (site) {
        targetSiteId = site.id;
        currentSiteId = site.id;
        currentSiteNameEl.textContent = site.label;
        renderSiteList();
      }
    }
  }

  // Ajouter les messages de process et de réponse
  if (targetSiteId) {
    if (!conversations[targetSiteId]) {
      conversations[targetSiteId] = [];
    }
    
    // Ajouter le message utilisateur s'il n'est pas déjà là
    const lastMsg = conversations[targetSiteId][conversations[targetSiteId].length - 1];
    if (!lastMsg || lastMsg.text !== prompt) {
      conversations[targetSiteId].push({
        from: "user",
        text: prompt
      });
    }
    
    // Ajouter les process steps si disponibles
    if (agentData.metadata && agentData.metadata.process_steps && agentData.metadata.process_steps.length > 0) {
      const processText = agentData.metadata.process_steps.join("\n");
      conversations[targetSiteId].push({
        from: "agent",
        text: processText,
        isProcess: true
      });
    }
    
    // Ajouter la réponse de l'agent (nettoyer le formatage Markdown)
    let cleanedReply = agentData.reply;
    
    // Retirer les backticks au début et à la fin
    cleanedReply = cleanedReply.trim();
    if (cleanedReply.startsWith('```')) {
      // Retirer le premier bloc de code
      cleanedReply = cleanedReply.replace(/^```[a-z]*\n?/i, '');
      // Retirer le dernier bloc de code
      cleanedReply = cleanedReply.replace(/\n?```$/i, '');
    }
    
    conversations[targetSiteId].push({
      from: "agent",
      text: cleanedReply
    });
    
    renderConversation();
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
      text: msg.content,
      isProcess: msg.role === "process"
    }));
    
    renderConversation();
    
  } catch (error) {
    console.error("Error loading site history:", error);
  }
}

// -------------------------------
// Event Listener : Bouton New Website
// -------------------------------
newWebsiteBtn.addEventListener("click", () => {
  // Désélectionner le site actuel
  currentSiteId = null;
  currentSiteNameEl.textContent = "Aucun site sélectionné";
  renderSiteList();
  renderConversation();
  
  // Focus sur l'input
  userInputEl.focus();
});

// -------------------------------
// Event Listener : Logo cliquable
// -------------------------------
appLogo.addEventListener("click", () => {
  // Confirmer avant de rafraîchir
  if (confirm("Voulez-vous vraiment rafraîchir la page ? Les conversations non sauvegardées seront perdues.")) {
    location.reload();
  }
});

// -------------------------------
// Initialisation
// -------------------------------
(async function init() {
  // Charger les sites depuis le backend
  await loadSitesFromBackend();
  
  renderSiteList();
  renderConversation();
})();