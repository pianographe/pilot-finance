# 🛡️ Rapport d'Audit - Pilot Finance v1.2.0

**Date de l'audit** : Janvier 2026  
**Version auditée** : 1.2.0  
**Auditeur** : Agent IA spécialisé (Red Team / Architecture / CNIL / Performance)

---

## 📋 Table des Matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Audit Sécurité (Red Team)](#2-audit-sécurité-red-team)
3. [Audit Architecture & Infrastructure](#3-audit-architecture--infrastructure)
4. [Audit Conformité CNIL/RGPD](#4-audit-conformité-cnilrgpd)
5. [Audit Performance](#5-audit-performance)
6. [Synthèse des Contremesures](#6-synthèse-des-contremesures)
7. [Conclusion](#7-conclusion)

---

## 1. Résumé Exécutif

### Points Positifs ✅
- Chiffrement AES-256-GCM des données sensibles (emails, noms de comptes, transactions)
- Utilisation de blind indexes pour les recherches sur données chiffrées
- Hachage bcrypt (10 rounds) pour les mots de passe
- Support Passkeys (WebAuthn) et 2FA (TOTP)
- Rate limiting avec verrouillage temporaire des comptes
- Session versioning permettant la révocation des sessions
- Tokens de vérification hachés (SHA-256)
- Build Docker multi-stage optimisé
- Validation forte des mots de passe (8+ chars, majuscule, minuscule, chiffre, caractère spécial)
- CI/CD avec CodeQL pour analyse de sécurité automatisée

### Points Critiques ❌
- **6 vulnérabilités de sécurité** identifiées (2 critiques, 3 moyennes, 1 mineure)
- **3 non-conformités RGPD** potentielles
- **4 axes d'amélioration architecture** recommandés
- **5 optimisations de performance** suggérées

---

## 2. Audit Sécurité (Red Team)

### 2.1 Vulnérabilités Critiques 🔴

#### VULN-001 : Fallback de Clés de Chiffrement en Mode Développement
**Fichier** : `build/src/lib/env.ts` (lignes 7-10)  
**Sévérité** : **CRITIQUE**

```typescript
if (process.env.NODE_ENV === 'development') {
   console.warn(`Missing env var: ${key}`);
   return 'dev-fallback-secret-key-change-me-immediately'; 
}
```

**Description** : En mode développement, si les clés `AUTH_SECRET`, `ENCRYPTION_KEY` ou `BLIND_INDEX_KEY` ne sont pas définies, une valeur statique prédictible est utilisée. Si une application est accidentellement déployée en mode développement, toutes les données chiffrées et sessions pourraient être compromises.

**Contremesure** :
- Supprimer totalement le fallback en mode développement
- Rendre le démarrage impossible sans les clés, même en dev
- Ajouter une vérification au démarrage que `NODE_ENV=production` si `HOST` est défini

---

#### VULN-002 : Dérivation Faible des Clés Non-Conformes
**Fichier** : `build/src/lib/crypto.ts` (lignes 5-10)  
**Sévérité** : **CRITIQUE**

```typescript
const SECRET_KEY = Buffer.from(ENV.ENCRYPTION_KEY, 'hex').length === 32 
    ? Buffer.from(ENV.ENCRYPTION_KEY, 'hex') 
    : createHash('sha256').update(ENV.ENCRYPTION_KEY).digest();
```

**Description** : Si une clé de chiffrement de taille incorrecte est fournie, elle est dérivée via un simple SHA-256 sans sel ni itérations. Cette pratique affaiblit considérablement la sécurité cryptographique. Un attaquant connaissant une clé faible pourrait plus facilement dériver la clé utilisée.

**Contremesure** :
- **Rejeter** toute clé ne faisant pas exactement 32 octets (64 caractères hex)
- Utiliser HKDF ou PBKDF2 si une dérivation est nécessaire
- Ajouter une validation stricte au démarrage

---

### 2.2 Vulnérabilités Moyennes 🟠

#### VULN-003 : Absence de Middleware de Protection Global
**Fichiers** : `build/src/proxy.ts`, `build/proxy.ts`  
**Sévérité** : **MOYENNE**

**Description** : Deux fichiers `proxy.ts` existent avec des implémentations différentes. De plus, aucun fichier `middleware.ts` n'est présent à la racine de `/src` ou `/`, ce qui signifie que Next.js ne l'active pas automatiquement. La protection des routes repose donc uniquement sur les vérifications dans chaque server action.

**Risque** : Les routes API ou pages pourraient être accessibles sans authentification appropriée si les server actions ne vérifient pas systématiquement la session.

**Contremesure** :
- Créer un vrai fichier `middleware.ts` à la racine de `src/`
- Supprimer le fichier `build/proxy.ts` obsolète
- Renommer `build/src/proxy.ts` en `build/src/middleware.ts`
- Ajouter la vérification de `sessionVersion` dans le middleware pour invalider les sessions obsolètes

---

#### VULN-004 : Absence de CSRF Protection Explicite
**Sévérité** : **MOYENNE**

**Description** : Les formulaires utilisent des Server Actions Next.js qui, par défaut, n'incluent pas de protection CSRF explicite. Bien que Next.js apporte une certaine protection via les cookies `SameSite=Lax`, une protection CSRF dédiée renforcerait la sécurité.

**Contremesure** :
- Implémenter des tokens CSRF pour les actions sensibles (changement de mot de passe, suppression de compte)
- Ou passer les cookies de session en `SameSite=Strict` (impact sur l'expérience utilisateur à évaluer)

---

#### VULN-005 : Logging d'Erreurs de Déchiffrement
**Fichier** : `build/src/lib/crypto.ts` (ligne 30)  
**Sévérité** : **MOYENNE**

```typescript
console.error("Decryption failed:", error);
```

**Description** : En cas d'erreur de déchiffrement, le message d'erreur complet est loggé. Cela pourrait exposer des informations sensibles (stack traces, données partielles) dans les logs.

**Contremesure** :
- Logger uniquement le type d'erreur, pas le détail
- Utiliser un système de logging structuré avec niveaux de sécurité
- Masquer les données sensibles dans les logs

---

### 2.3 Vulnérabilités Mineures 🟡

#### VULN-006 : Utilisation de `latest` pour Toutes les Dépendances
**Fichier** : `build/package.json`  
**Sévérité** : **MINEURE** (mais risque opérationnel élevé)

```json
"dependencies": {
    "@neondatabase/serverless": "latest",
    "@otplib/preset-default": "latest",
    ...
}
```

**Description** : Toutes les dépendances dans `package.json` spécifient `latest` au lieu de versions explicites. Bien que `package-lock.json` verrouille les versions en production, cette pratique peut introduire des breaking changes ou des vulnérabilités non testées lors des builds ou si le lockfile est régénéré.

**Contremesure** :
- Versionner les dépendances explicitement (ex: `"next": "^15.0.0"`)
- Conserver `package-lock.json` pour verrouiller les versions (déjà présent ✅)
- Configurer Renovate/Dependabot pour les mises à jour contrôlées (Dependabot déjà configuré ✅)

---

### 2.4 Points Positifs en Sécurité ✅

| Mécanisme | Implémentation | Évaluation |
|-----------|---------------|------------|
| Hachage mot de passe | bcrypt 10 rounds | ✅ Conforme |
| Chiffrement données | AES-256-GCM avec IV aléatoire | ✅ Excellent |
| Blind Index | HMAC-SHA256 | ✅ Bonne pratique |
| Protection brute-force | 5 tentatives, blocage 15 min | ✅ Conforme |
| Session JWT | HS256, expiration 24h | ✅ Acceptable |
| Cookies | HttpOnly, Secure, SameSite=Lax | ✅ Conforme |
| Passkeys | WebAuthn implémenté | ✅ Excellent |
| 2FA TOTP | otplib avec secret chiffré | ✅ Conforme |
| Session Versioning | Invalidation après changement mot de passe | ✅ Bonne pratique |

---

## 3. Audit Architecture & Infrastructure

### 3.1 Points d'Amélioration Architecture 🏗️

#### ARCH-001 : Dockerfile - Image de Base
**Fichier** : `build/Dockerfile`

**Observation** : Utilisation de `node:22-alpine` qui est une bonne pratique, mais la version exacte n'est pas fixée (risque de changements inattendus).

**Contremesure** :
```dockerfile
FROM node:22.12-alpine AS deps
```
Fixer une version mineure spécifique.

---

#### ARCH-002 : Absence de Healthcheck Applicatif
**Fichier** : `build/Dockerfile`

**Observation** : Aucun `HEALTHCHECK` dans le Dockerfile. Le healthcheck est défini dans `docker-compose.yml.example` mais pas dans l'image elle-même.

**Contremesure** :
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/login || exit 1
```

---

#### ARCH-003 : Absence de Scan de Vulnérabilités Docker
**Fichier** : `.github/workflows/docker-publish.yml`

**Observation** : Le workflow CI/CD ne scanne pas l'image Docker pour les vulnérabilités connues (CVE).

**Contremesure** :
```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
    format: 'sarif'
    output: 'trivy-results.sarif'
```

---

#### ARCH-004 : Duplication de Code - Validation Mot de Passe
**Fichiers** : `build/src/actions/auth-actions.ts` (lignes 21-28), `build/src/actions/user-actions.ts` (lignes 25-31)

**Observation** : La fonction `validatePasswordStrength` est dupliquée dans deux fichiers.

**Contremesure** :
- Créer un fichier `build/src/lib/validation.ts`
- Centraliser les fonctions de validation

---

### 3.2 Points Positifs Architecture ✅

| Aspect | Évaluation |
|--------|------------|
| Build multi-stage Docker | ✅ Excellent (3 étapes optimisées) |
| Exécution utilisateur non-root | ✅ `USER node` |
| Next.js standalone output | ✅ Image légère |
| Drizzle ORM avec types | ✅ Type-safe |
| Index SQL définis | ✅ Performance BDD |
| CodeQL CI/CD | ✅ Analyse sécurité automatisée |
| Dependabot | ✅ Mises à jour dépendances |

---

## 4. Audit Conformité CNIL/RGPD

### 4.1 Non-Conformités Potentielles ⚖️

#### RGPD-001 : Absence de Politique de Confidentialité Intégrée
**Sévérité** : **HAUTE** (obligation légale)

**Observation** : Aucune page de politique de confidentialité n'est présente dans l'application. Selon le RGPD (Article 13/14), les utilisateurs doivent être informés du traitement de leurs données.

**Contremesure** :
- Créer une page `/privacy-policy` accessible avant inscription
- Inclure : finalités, base légale, durée de conservation, droits RGPD
- Ajouter une case à cocher à l'inscription

---

#### RGPD-002 : Absence de Mécanisme de Suppression de Compte
**Sévérité** : **HAUTE** (Droit à l'effacement - Article 17)

**Observation** : Seul un administrateur peut supprimer un utilisateur (`deleteUser` dans `user-actions.ts`). Un utilisateur ne peut pas supprimer son propre compte.

**Contremesure** :
- Ajouter une fonction `deleteOwnAccount()` dans les actions utilisateur
- Permettre aux utilisateurs de demander la suppression depuis `/settings`
- Implémenter une période de grâce de 30 jours avant suppression définitive

---

#### RGPD-003 : Absence d'Export des Données Personnelles
**Sévérité** : **MOYENNE** (Droit à la portabilité - Article 20)

**Observation** : Aucun mécanisme ne permet à l'utilisateur d'exporter ses données (comptes, transactions, opérations récurrentes).

**Contremesure** :
- Ajouter une fonction `exportUserData()` dans les server actions
- Générer un fichier JSON/CSV téléchargeable
- Accessible depuis `/settings`

---

### 4.2 Points de Conformité Positifs ✅

| Exigence RGPD | Implémentation | Évaluation |
|---------------|---------------|------------|
| Minimisation des données | Seules données nécessaires collectées | ✅ |
| Chiffrement (Art. 32) | AES-256-GCM + données au repos chiffrées | ✅ Excellent |
| Pseudonymisation | Blind index pour emails | ✅ |
| Sécurité accès (Art. 32) | MFA, Passkeys, rate limiting | ✅ |
| auto-hébergement | Pas de transfert vers services tiers | ✅ Excellent |
| Contrôle accès | RBAC (USER/ADMIN) | ✅ |
| Journalisation | Transactions loggées | ⚠️ Partiel |

---

### 4.3 Recommandations Supplémentaires RGPD

1. **Registre de traitement** : Documenter les traitements dans un fichier `TRAITEMENTS.md`
2. **Durée de conservation** : Définir et implémenter une politique de rétention des données
3. **Consentement explicite** : Ajouter un consentement éclairé lors de l'inscription
4. **Notification de violation** : Préparer un processus de notification en cas de fuite de données

---

## 5. Audit Performance

### 5.1 Points d'Optimisation 🚀

#### PERF-001 : Rechargement Complet des Données Dashboard
**Fichier** : `build/src/app/page.tsx`

```typescript
useEffect(() => {
    const timer = setTimeout(() => {
        getDashboardData(sliderValue).then(setData);
    }, 500);
    return () => clearTimeout(timer);
}, [sliderValue]);
```

**Observation** : Chaque changement du slider déclenche un rechargement complet des données après 500ms. Les calculs de projection sont refaits côté serveur.

**Contremesure** :
- Séparer `getDashboardData` en deux fonctions : une pour les comptes (cache de longue durée), une pour les projections
- Effectuer les calculs de projection côté client
- Utiliser `useMemo` pour les recalculs

---

#### PERF-002 : Requêtes N+1 dans les Opérations Récurrentes
**Fichier** : `build/src/actions/budget-actions.ts` (fonction `checkRecurringOperations`)

**Observation** : Dans la boucle des opérations récurrentes, chaque opération déclenche des requêtes individuelles (`SELECT`, `UPDATE`, `INSERT`).

**Contremesure** :
- Regrouper les opérations par batch
- Utiliser des transactions SQL
- Pré-charger les comptes concernés en une seule requête

---

#### PERF-003 : Simulation de Projection Non Mémorisée
**Fichier** : `build/src/actions/budget-actions.ts` (fonction `simulateProjection`)

**Observation** : La projection sur 30 ans parcourt 360 mois avec des calculs répétés à chaque itération sans mise en cache.

**Contremesure** :
- Pour une même configuration de comptes, mettre en cache les résultats de projection
- Limiter la granularité (mensuelle pour < 3 ans, annuelle au-delà) - déjà partiellement fait ✅
- Envisager un calcul client-side pour la réactivité

---

#### PERF-004 : Imports Dynamiques Répétés
**Fichier** : `build/src/actions/auth-actions.ts`

```typescript
const { hash, compare } = await import('bcryptjs');
const { randomBytes } = await import('crypto');
```

**Observation** : Les modules sont importés dynamiquement à chaque appel de fonction. Bien que cela optimise le cold start, en production avec des appels fréquents, cela ajoute une latence.

**Contremesure** :
- Conserver les imports dynamiques mais créer un module wrapper qui met en cache les imports après le premier chargement
- Alternative : imports statiques pour les modules fréquemment utilisés

---

#### PERF-005 : Absence de Cache HTTP
**Fichier** : `build/src/app/page.tsx`

```typescript
export const dynamic = 'force-dynamic';
```

**Observation** : La page dashboard est entièrement dynamique. Les données ne bénéficient d'aucun cache, même pour des éléments stables.

**Contremesure** :
- Utiliser `unstable_cache` de Next.js pour les données stables (liste des comptes)
- Implémenter `stale-while-revalidate` pour une meilleure UX

---

### 5.2 Points Positifs Performance ✅

| Aspect | Évaluation |
|--------|------------|
| Index SQL | ✅ Excellents (userId, accountId, date, tokens) |
| Debounce slider | ✅ 500ms évite les requêtes excessives |
| Build standalone | ✅ Image légère et démarrage rapide |
| Server Actions | ✅ Pas d'API routes inutiles |
| Client Components ciblés | ✅ Hydratation optimisée |

---

## 6. Synthèse des Contremesures

### Priorité Critique (à corriger immédiatement) 🔴

| ID | Vulnérabilité | Contremesure | Effort |
|----|--------------|--------------|--------|
| VULN-001 | Fallback clés en dev | Supprimer le fallback | 0.5h |
| VULN-002 | Dérivation clé faible | Rejeter clés non conformes | 1h |

### Priorité Haute (sous 30 jours) 🟠

| ID | Vulnérabilité | Contremesure | Effort |
|----|--------------|--------------|--------|
| VULN-003 | Middleware manquant | Créer `middleware.ts` | 2h |
| RGPD-001 | Politique confidentialité | Créer page légale | 4h |
| RGPD-002 | Suppression compte | Fonction `deleteOwnAccount` | 3h |

### Priorité Moyenne (sous 90 jours) 🟡

| ID | Vulnérabilité | Contremesure | Effort |
|----|--------------|--------------|--------|
| VULN-004 | Protection CSRF | Tokens CSRF ou `SameSite=Strict` | 3h |
| VULN-005 | Logging erreurs | Logging structuré | 2h |
| RGPD-003 | Export données | Fonction export JSON/CSV | 4h |
| ARCH-001 | Version Docker | Fixer version Node.js | 0.5h |
| ARCH-002 | Healthcheck Docker | Ajouter au Dockerfile | 0.5h |
| ARCH-003 | Scan vulnérabilités | Intégrer Trivy | 1h |
| ARCH-004 | Duplication code | Centraliser validation | 1h |

### Optimisations (backlog) 💡

| ID | Amélioration | Contremesure | Effort |
|----|-------------|--------------|--------|
| PERF-001 | Cache dashboard | Séparer données/projections | 3h |
| PERF-002 | N+1 queries | Batch/transactions | 4h |
| PERF-003 | Cache projections | Mémoisation | 2h |
| VULN-006 | Versions `latest` | Versionner dépendances | 1h |

---

## 7. Conclusion

### Évaluation Globale

| Domaine | Score | Commentaire |
|---------|-------|-------------|
| **Sécurité** | 7/10 | Bonnes bases, mais vulnérabilités critiques à corriger |
| **Architecture** | 8/10 | Solide, quelques améliorations mineures |
| **Conformité RGPD** | 5/10 | Chiffrement excellent, mais droits utilisateurs manquants |
| **Performance** | 7/10 | Acceptable, optimisations possibles |
| **GLOBAL** | **6.75/10** | Application bien conçue nécessitant des corrections ciblées |

### Verdict

**Pilot Finance v1.2.0** est une application **bien pensée sur le plan sécurité** avec un chiffrement fort et des mécanismes d'authentification modernes (Passkeys, 2FA). Cependant, **deux vulnérabilités critiques** liées à la gestion des clés de chiffrement doivent être corrigées en priorité absolue.

Sur le plan **RGPD**, l'application bénéficie de l'auto-hébergement et du chiffrement, mais nécessite l'implémentation des **droits utilisateurs** (suppression, portabilité, information).

L'**architecture Docker** est propre et optimisée, avec des points d'amélioration mineurs sur la gestion des versions et le healthcheck.

La **performance** est satisfaisante pour un usage personnel, avec des axes d'optimisation identifiés pour un usage plus intensif.

---

**Recommandation finale** : Corriger les vulnérabilités VULN-001 et VULN-002 avant tout déploiement en production, puis planifier les corrections RGPD selon le calendrier suggéré.

---

*Ce rapport a été généré par une analyse automatisée et doit être validé par un expert humain avant toute action.*
