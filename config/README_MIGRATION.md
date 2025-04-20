# Guide de migration de la base de données pour l'authentification unifiée

Ce document explique comment migrer la structure de la base de données pour supporter le nouveau système d'authentification unifiée qui permet à la fois l'authentification standard et Google OAuth.

## Préparation

1. **Sauvegarde de la base de données**
   - Avant toute modification, faites une sauvegarde complète de votre base de données
   - Dans phpMyAdmin : Sélectionnez la base de données > Exporter > Format SQL > Exporter

2. **Vérification des dépendances**
   - Assurez-vous que toutes les dépendances du projet sont installées :
   ```
   composer update
   ```

## Exécution de la migration

### Option 1 : Utilisation de phpMyAdmin (recommandée)

1. Connectez-vous à phpMyAdmin
2. Sélectionnez votre base de données `medconnectdb`
3. Cliquez sur l'onglet "SQL"
4. Copiez et collez le contenu du fichier `config/migration_auth.sql`
5. Cliquez sur "Exécuter"

### Option 2 : Ligne de commande MySQL

```bash
mysql -u [username] -p medconnectdb < config/migration_auth.sql
```

## Étapes de la migration

Le script de migration effectue les opérations suivantes :

1. **Création de la structure unifiée**
   - Table `users` centralisée pour tous les utilisateurs
   - Tables relationnelles `patients`, `medecins`, `admins` liées à `users`
   - Table `sessions` pour suivre les sessions actives
   - Table `login_attempts` pour surveiller les tentatives de connexion

2. **Migration des données existantes**
   - Transfère les utilisateurs des anciennes tables vers la nouvelle structure
   - Préserve tous les comptes et mots de passe existants

3. **Indexation et optimisation**
   - Ajoute des index pour optimiser les performances

## Vérification post-migration

Après avoir exécuté le script de migration, vérifiez que :

1. La table `users` contient tous les utilisateurs des anciennes tables
2. Les tables `patients`, `medecins` et `admins` sont correctement liées à `users`
3. L'authentification standard continue de fonctionner
4. L'authentification Google fonctionne correctement

## Problèmes potentiels et solutions

### Erreur de clé étrangère lors de la migration des données

Si vous rencontrez des erreurs liées aux contraintes de clé étrangère, vous pouvez désactiver temporairement la vérification des clés étrangères :

```sql
SET FOREIGN_KEY_CHECKS=0;
-- Exécuter les commandes de migration
SET FOREIGN_KEY_CHECKS=1;
```

### Conflits d'identifiants

Si vous avez des utilisateurs avec la même adresse email dans différentes tables, le script ne migrera que la première occurrence. Vous devrez résoudre ces conflits manuellement.

## Important

Les anciennes tables (`patient`, `medecin`, `admin`) ne sont pas supprimées dans cette migration afin de faciliter le retour en arrière en cas de problème. Une fois que vous avez vérifié que tout fonctionne correctement, vous pouvez envisager de les supprimer ou de les conserver comme référence historique. 