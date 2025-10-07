# Disco Maghreb - Intro

## Write-up

### 1. MCP, c'est quoi ?

MCP (*Model Context Protocol*) est un protocole standard qui permet de communiquer entre un client et un serveur, un peu comme une API, mais pensé pour s'intégrer facilement aux LLM et aux outils.

* Un **serveur MCP** expose des fonctionnalités appelées des **tools**.
* Un **client MCP** peut se connecter au serveur, lister les tools disponibles, et les appeler avec certains paramètres.
* Chaque tool est documenté (description, arguments attendus, type de retour).

Pour ce challenge, le serveur MCP tourne sur le port **8080** et expose un outil qu'il faut découvrir.

---

### 2. Reconnaissance

On commence par écrire un client MCP. La bibliothèque [FastMCP](https://gofastmcp.com/getting-started/welcome) permet de communiquer facilement avec un serveur MCP en Python.

On instancie le client :

```python
from fastmcp import Client
client = Client("http://127.0.0.1:8080/mcp")
```

Avant toute chose, on peut tester la connexion avec un `ping()`.

---

### 3. Découverte des tools

Ensuite, la méthode clé est **`list_tools()`** : elle permet d'afficher la liste de tous les tools exposés par le serveur.
En listant les tools disponibles, on obtient (output simplifié) :

```json
{
    "name": "get_flag",
    "description": "Get the first flag, if you want !",
    "inputSchema": {
        "properties": {
            "i_want_flag": {
                "default": false,
                "title": "I Want Flag",
                "type": "boolean"
            }
        },
        ...
    }
}
```

On voit qu'un seul tool est disponible : **`get_flag`**.
Il prend un argument booléen `i_want_flag` qui doit probablement être mis à `True` pour obtenir quelque chose d'intéressant.

---

### 4. Exploitation du tool

Pour appeler un tool, on utilise la méthode `call_tool()` du client :

```python
result = await client.call_tool("get_flag", {"i_want_flag": True})
print(result.structured_content)
```

En envoyant la requête avec `i_want_flag = True`, le serveur nous renvoie directement :

```
flag-MCP_1s_n07_s0_d1ff1cul7-Fn99RLq5
```

## Flag

`flag-MCP_1s_n07_s0_d1ff1cul7-Fn99RLq5`
