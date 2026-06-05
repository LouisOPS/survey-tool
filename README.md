# Survey Tool — Outil de sondage Amazon

Application web de sondage pour associates Amazon.
Déployée sur [Render.com](https://render.com) avec PostgreSQL.

## Déploiement rapide (Render)

1. **Fork/upload** ce repo sur GitHub
2. Sur [render.com](https://render.com) → New → Blueprint → connecter le repo
3. Render lit `render.yaml` et crée automatiquement :
   - Le service web Node.js
   - La base de données PostgreSQL (gratuite 90 jours)
4. Après le premier déploiement, aller dans les **variables d'environnement** du service et ajouter :
   ```
   PUBLIC_URL = https://survey-tool-XXXX.onrender.com
   ```
   (remplacer par l'URL affichée par Render)

## Connexion admin

- URL : `https://your-app.onrender.com/admin`
- Mot de passe par défaut : `admin123`
- **À changer immédiatement** depuis le dashboard admin

## Fonctionnement

- L'admin crée des sondages avec des questions (radio, checkbox, texte libre, note /5)
- Chaque sondage génère un QR code que les associates scannent
- L'associate entre son login Amazon et répond (aucun compte requis)
- Les réponses sont visibles en temps réel dans le dashboard admin
- Export Excel disponible

## Variables d'environnement

| Variable | Description | Obligatoire |
|---|---|---|
| `DATABASE_URL` | Fournie automatiquement par Render | Oui |
| `PUBLIC_URL` | URL publique de l'app (pour les QR codes) | Oui |
| `SESSION_SECRET` | Généré automatiquement par Render | Oui |
| `PORT` | Fourni automatiquement par Render | Non |
