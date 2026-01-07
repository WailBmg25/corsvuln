# Projet de Démonstration des Vulnérabilités CORS

⚠️ **À DES FINS ÉDUCATIVES UNIQUEMENT** ⚠️

**AVERTISSEMENT** : Cette application contient des endpoints intentionnellement vulnérables à des fins éducatives uniquement. Ne jamais déployer cette application dans un environnement de production ou sur un réseau accessible publiquement.

## Vue d'Ensemble

Le Projet de Démonstration des Vulnérabilités CORS est une application FastAPI éducative qui démontre des mauvaises configurations CORS (Cross-Origin Resource Sharing) réelles et leurs implications en matière de sécurité. Ce projet présente à la fois des implémentations vulnérables et sécurisées avec des scripts d'attaque Python correspondants qui prouvent les vulnérabilités.

Cet outil de démonstration est conçu pour l'éducation en sécurité, la formation et la recherche. Il aide les développeurs et les professionnels de la sécurité à comprendre les vulnérabilités CORS et à apprendre comment implémenter des configurations CORS sécurisées.

### Fonctionnalités Clés

- **Endpoints Vulnérables** : Implémentations CORS intentionnellement mal configurées démontrant des problèmes de sécurité courants
- **Endpoints Sécurisés** : Implémentations CORS correctement configurées montrant les meilleures pratiques
- **Scripts d'Attaque** : Scripts Python automatisés qui exploitent chaque type de vulnérabilité
- **Interface de Démonstration Interactive** : Tableau de bord web pour visualiser et exécuter des attaques en temps réel
- **Contenu Éducatif** : Explications détaillées avec références aux publications MISC 98, 99 et HS 4
- **Mécanismes de Sécurité** : Rate limiting, timeouts et sanitization pour assurer une démonstration sûre

## Démarrage Rapide

### Utilisation avec Docker (Recommandé)

```bash
# Cloner le dépôt
git clone git@github.com:WailBmg25/corsvuln.git
cd corsvuln

# Copier les variables d'environnement
cp .env.example .env

# Construire et lancer avec Docker Compose
docker-compose up --build

# Accéder à l'application
# Ouvrir http://localhost:8000 dans votre navigateur
```

### Développement Local

```bash
# Créer et activer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Copier les variables d'environnement
cp .env.example .env

# Lancer l'application
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Accéder à l'application
# Ouvrir http://localhost:8000 dans votre navigateur
```

### Comptes de Test par Défaut

L'application s'initialise avec trois comptes de test pour la démonstration :

- **Admin** : `admin` / `admin123` (privilèges complets)
- **User** : `user` / `user123` (privilèges limités)
- **Victim** : `victim` / `victim123` (utilisateur standard pour les démonstrations)

## Types de Vulnérabilités

Ce projet démontre cinq mauvaises configurations CORS majeures basées sur les publications MISC :

### 1. Origine Wildcard avec Credentials (`/api/vuln/wildcard`)

**Vulnérabilité** : Utilisation de `Access-Control-Allow-Origin: *` avec credentials activés

**Référence** : MISC 99

**Impact** : Permet des attaques par force brute contre les endpoints d'authentification et permet à n'importe quel site web malveillant de voler les credentials et tokens de session des utilisateurs.

**Commande curl exemple** :
```bash
curl -X GET 'http://localhost:8000/api/vuln/wildcard' \
  -H 'Origin: https://evil.com' \
  -H 'Cookie: session_id=votre_session_id' \
  -v
```

**Alternative Sécurisée** (`/api/sec/wildcard`) : Utilise une liste blanche d'origines spécifiques avec correspondance exacte

---

### 2. Réflexion d'Origine Sans Validation (`/api/vuln/reflection`)

**Vulnérabilité** : Réflexion de la valeur de l'en-tête Origin directement dans `Access-Control-Allow-Origin` sans validation

**Référence** : MISC 99

**Impact** : Permet aux attaquants de voler des données sensibles en effectuant des requêtes cross-origin authentifiées depuis des sites web malveillants. C'est l'une des mauvaises configurations CORS les plus courantes.

**Commande curl exemple** :
```bash
curl -X POST 'http://localhost:8000/api/vuln/reflection' \
  -H 'Origin: https://attacker.com' \
  -H 'Cookie: session_id=votre_session_id' \
  -H 'Content-Type: application/json' \
  -d '{}' \
  -v
```

**Alternative Sécurisée** (`/api/sec/reflection`) : Valide les origines contre une liste blanche prédéfinie avec correspondance exacte

---

### 3. Acceptation d'Origine Null (`/api/vuln/null-origin`)

**Vulnérabilité** : Acceptation de `Origin: null` depuis des iframes sandboxées ou des fichiers locaux

**Référence** : MISC 99

**Impact** : Permet aux attaquants de contourner les protections CORS en utilisant des iframes sandboxées ou des fichiers HTML locaux. Les origines null sont faciles à générer et à exploiter.

**Commande curl exemple** :
```bash
curl -X GET 'http://localhost:8000/api/vuln/null-origin' \
  -H 'Origin: null' \
  -H 'Cookie: session_id=votre_session_id' \
  -v
```

**Alternative Sécurisée** (`/api/sec/null-origin`) : Rejette explicitement les origines null avec 403 Forbidden

---

### 4. Filtrage Permissif par Sous-chaîne (`/api/vuln/permissive`)

**Vulnérabilité** : Utilisation de correspondance de sous-chaîne (ex: vérifier si l'origine contient "trusted.com") au lieu d'une correspondance exacte

**Référence** : MISC 99

**Impact** : Permet aux attaquants d'enregistrer des domaines malveillants comme `attacker-trusted.com` ou `trusted.com.evil.com` pour contourner la validation.

**Commande curl exemple** :
```bash
curl -X GET 'http://localhost:8000/api/vuln/permissive' \
  -H 'Origin: https://attacker-trusted.com' \
  -H 'Cookie: session_id=votre_session_id' \
  -v
```

**Alternative Sécurisée** (`/api/sec/permissive`) : Utilise une correspondance exacte de chaîne incluant le protocole et le port

---

### 5. En-tête Vary Manquant - Empoisonnement de Cache (`/api/vuln/vary`)

**Vulnérabilité** : Servir différents en-têtes CORS basés sur Origin sans inclure l'en-tête `Vary: Origin`

**Référence** : MISC 99

**Impact** : Permet aux attaquants d'empoisonner les caches avec des en-têtes CORS malveillants, causant aux utilisateurs légitimes de recevoir des réponses avec l'origine de l'attaquant.

**Commande curl exemple** :
```bash
curl -X GET 'http://localhost:8000/api/vuln/vary' \
  -H 'Origin: https://attacker.com' \
  -H 'Cookie: session_id=votre_session_id' \
  -v
```

**Alternative Sécurisée** (`/api/sec/vary`) : Inclut `Vary: Origin` et des en-têtes de contrôle de cache appropriés

---

## Scripts d'Attaque

Le projet inclut des scripts d'attaque automatisés qui démontrent l'exploitation de chaque vulnérabilité :

### Utilisation CLI

```bash
# Exécuter une attaque sur l'endpoint vulnérable
python run_attack_cli.py wildcard

# Exécuter une attaque sur l'endpoint sécurisé
python run_attack_cli.py wildcard --secure

# Autres types d'attaques disponibles
python run_attack_cli.py reflection
python run_attack_cli.py null_origin
python run_attack_cli.py permissive
python run_attack_cli.py vary
```

## Structure du Projet

```
corsvuln/
├── app/                    # Application FastAPI
│   ├── auth/              # Module d'authentification
│   ├── middleware/        # Middleware CORS
│   ├── models/            # Modèles de données
│   ├── routers/           # Routes API (vulnérables & sécurisées)
│   └── utils/             # Utilitaires (sanitization, etc.)
├── attacks/               # Scripts d'attaque
│   ├── brute_force.py    # Attaque wildcard
│   ├── reflection.py     # Attaque par réflexion d'origine
│   ├── null_origin.py    # Attaque origine null
│   ├── permissive.py     # Attaque filtrage permissif
│   └── vary_attack.py    # Attaque en-tête Vary
├── static/                # Assets frontend (CSS, JS)
├── templates/             # Templates HTML
├── educational_content.json  # Contenu éducatif
├── main.py               # Point d'entrée de l'application
├── run_attack_cli.py     # CLI pour exécuter les attaques
└── requirements.txt      # Dépendances Python
```

## Recommandations de Sécurité

### Pour les Développeurs

1. **Ne jamais utiliser wildcard origin avec credentials** : Toujours utiliser des listes blanches d'origines spécifiques
2. **Valider les origines strictement** : Utiliser une correspondance exacte de chaîne incluant le protocole et le port
3. **Rejeter les origines null** : Rejeter explicitement `Origin: null` avec le statut 403
4. **Inclure l'en-tête Vary** : Toujours inclure `Vary: Origin` quand les en-têtes CORS dépendent de l'origine
5. **Utiliser un contrôle de cache approprié** : Empêcher la mise en cache de données sensibles avec des en-têtes appropriés

### Pour les Professionnels de la Sécurité

1. **Tester les mauvaises configurations CORS** : Inclure les tests CORS dans les évaluations de sécurité
2. **Rechercher la réflexion d'origine** : Vérifier si les applications reflètent l'en-tête Origin sans validation
3. **Tester avec des origines null** : Vérifier que les applications rejettent correctement les origines null
4. **Vérifier la correspondance de sous-chaîne** : Tester avec des domaines malveillants contenant des sous-chaînes de confiance
5. **Vérifier les en-têtes Vary** : S'assurer que les applications incluent des en-têtes Vary appropriés pour les réponses en cache

## Avertissements de Déploiement

⚠️ **AVERTISSEMENTS DE SÉCURITÉ CRITIQUES** ⚠️

Cette application est conçue à **des fins éducatives uniquement** et ne doit **JAMAIS** être déployée dans :

- Environnements de production
- Réseaux accessibles publiquement
- Tout environnement avec des données utilisateur réelles
- Tout environnement connecté à Internet

### Environnements de Déploiement Recommandés

✅ **Environnements Sûrs** :
- Environnement de développement local isolé
- Salle de classe ou laboratoire de formation avec isolation réseau
- Conteneur Docker sans accès réseau externe
- Machines virtuelles sur réseaux isolés
- Accès localhost uniquement

## Documentation API

Une fois l'application lancée, accédez à la documentation API interactive :

- **Swagger UI** : http://localhost:8000/docs
- **ReDoc** : http://localhost:8000/redoc

## Références

Ce projet est basé sur la recherche et les publications du magazine français de sécurité MISC :

### Références Principales

- **MISC 98** : "Comprendre le fonctionnement des CORS"
- **MISC 99** : "Cross Origin Resource Sharing: défauts de configurations, vulnérabilités et exploitations"
- **MISC HS 4** : "Architectures web sécurisées"

### Ressources Additionnelles

- **MDN Web Docs - CORS** : https://developer.mozilla.org/fr/docs/Web/HTTP/CORS
- **OWASP - CORS** : https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny

## Contribution

Ceci est un projet éducatif. Si vous trouvez des problèmes ou avez des suggestions d'amélioration, veuillez ouvrir une issue ou soumettre une pull request.

## Licence

Ce projet est à des fins éducatives uniquement. Utilisez de manière responsable et uniquement dans des environnements autorisés.

## Remerciements

Basé sur la recherche des publications MISC 98, 99 et HS 4. Merci spécial à la communauté de recherche en sécurité pour avoir documenté ces vulnérabilités et aidé à améliorer la sécurité web.

---

**Rappel** : Cette application contient du code intentionnellement vulnérable. Ne jamais utiliser ces patterns dans des applications de production. Toujours implémenter des configurations CORS sécurisées en suivant les exemples sécurisés fournis dans ce projet.
