# API Server Guide

## Structure du serveur

```
cyber-security/server/
├── __init__.py          # Package initialization
├── main.py              # Application FastAPI principale
├── schemas.py           # Modèles Pydantic (Request/Response)
├── dependencies.py      # Dépendances et injection
└── models.py            # Modèles de données additionnels
```

## Endpoints disponibles

### 1. Health Check
- **GET** `/` - Status de l'API
- **GET** `/api/health` - Health check détaillé

### 2. Chat avec l'agent IA
- **POST** `/api/agent`
  - Body: `{ "prompt": "string", "currentSite": "string?" }`
  - Response: `{ "site": "string", "reply": "string", "metadata": {} }`

### 3. Gestion des sites
- **GET** `/api/sites` - Liste de tous les sites analysés
- **GET** `/api/sites/{site_id}` - Détails d'un site spécifique
- **GET** `/api/sites/{site_id}/history` - Historique complet (conversation + résultats)
- **DELETE** `/api/sites/{site_id}` - Supprimer un site et ses données

## Démarrage du serveur

### Option 1: Démarrage direct
```bash
cd cyber-security
python -m uvicorn server.main:app --reload --host 0.0.0.0 --port 8000
```

### Option 2: Avec le script Python
```bash
cd cyber-security/server
python main.py
```

### Option 3: En production
```bash
cd cyber-security
uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## Configuration requise

1. **Installer les dépendances:**
```bash
cd cyber-security
pip install -r requirements.txt
```

2. **Variables d'environnement** (fichier `.env`):
```env
DATABASE_URL=sqlite:///./cybersecurity.db
# ou pour PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/cybersecurity
```

## Frontend - Mise à jour

Le fichier `script.js` a été mis à jour pour utiliser l'API:

```javascript
// Appel à l'API FastAPI
const response = await fetch("http://localhost:8000/api/agent", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    prompt: userMessage,
    currentSite: currentSiteUrl
  })
});
```

## CORS Configuration

Le serveur accepte les requêtes de:
- `http://localhost:3000`
- `http://localhost:5500`
- `http://127.0.0.1:5500`
- `http://localhost:8000`

Pour ajouter d'autres origines, modifiez `server/main.py`:
```python
allow_origins=[
    "http://votre-domaine.com",
    # ...
]
```

## Test de l'API

### Avec curl:
```bash
# Test health check
curl http://localhost:8000/api/health

# Test chat
curl -X POST http://localhost:8000/api/agent \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Analyse facebook.com pour les vulnérabilités XSS"}'

# Liste des sites
curl http://localhost:8000/api/sites
```

### Avec Python:
```python
import requests

response = requests.post(
    "http://localhost:8000/api/agent",
    json={
        "prompt": "Analyse facebook.com",
        "currentSite": None
    }
)
print(response.json())
```

## Documentation interactive

Une fois le serveur démarré, accédez à:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Workflow complet

1. **Démarrer le serveur:**
   ```bash
   cd cyber-security
   python -m uvicorn server.main:app --reload
   ```

2. **Ouvrir le frontend:**
   - Ouvrir `index.html` dans le navigateur
   - Ou utiliser Live Server de VS Code

3. **Utiliser l'application:**
   - Entrer un prompt: "Analyse example.com pour XSS"
   - L'agent IA traite la requête
   - Les résultats s'affichent dans le chat
   - Le site est ajouté à la liste latérale

## Troubleshooting

### Port déjà utilisé
```bash
# Changer le port
uvicorn server.main:app --reload --port 8001
# Mettre à jour l'URL dans script.js
```

### CORS errors
Vérifier que le serveur est bien démarré et que l'origine est autorisée dans `main.py`

### Database errors
Vérifier que la variable `DATABASE_URL` est correctement définie dans `.env`

## Prochaines étapes

- [ ] Ajouter authentification JWT
- [ ] Implémenter rate limiting
- [ ] Ajouter WebSocket pour les updates en temps réel
- [ ] Déployer sur un serveur de production
- [ ] Ajouter monitoring et logging avancé
