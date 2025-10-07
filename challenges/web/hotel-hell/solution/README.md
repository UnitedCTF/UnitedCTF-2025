# Hotel hell

## Write-up

Dans tout challenge, c'est une bonne idée de commencer par trouver l'objectif final. Après on peut travailler à l'envers et se rendre jusqu'à la solution.

Dans le cas de ce défi, on voit dans le `Dockerfile` que le flag est écrit dans `/flag.txt`. En regardant un peu le code, on voit un comportement risqué qui pourrait être pertinent, soit l'insertion du code de chambre dans un fichier de configuration utilisé par [ripgrep](https://github.com/BurntSushi/ripgrep) ou `rg`.

```js
async function checkBreached(roomCode) {
    const configTemplate = fs.readFileSync('template.cfg').toString();
    const config = Buffer.from(configTemplate.replace('%s', roomCode));

    const configFile = tmp.fileSync();
    fs.writeSync(configFile.fd, config);

    // La ligne intéressante
    const searchProc = child_process.spawn('/usr/bin/rg', ['breached-rooms.lst.gz'], {
        env: { 'RIPGREP_CONFIG_PATH': configFile.name }
    });

    const exitCode = await new Promise((resolve, _) => searchProc.on('close', resolve));

    configFile.removeCallback();

    // ...
}
```

Si on retrace l'arbre d'appel, on voit qu'il faut passer par `POST /api/check`, que le code de chambre soit validé par `validateRoomCode` et ensuite que la combinaison du code de chambre et de la clé de chambre soit validée par `validateRoomKey`.

### `validateRoomCode`
Voici la fonction `validateRoomCode`:

```js
const CHAR_BLACKLIST = /[^\d]/g;

// ...

function validateRoomCode(roomCode) {
    if(!roomCode.startsWith('CBG:')) return false;
    if(CHAR_BLACKLIST.test(roomCode.substring(4))) return false;
    return true;
}
```

La première clause vérifie que le code de chambre commence par `CBG:`. La deuxième applique l'expression régulière `/[^\d]/g` sur ce qui suit `CBG:` et si un le test est concluant, la validation échoue. En d'autres mots, on dirait que le code de chambre doit suivre le format `CBG:\d+` (d'ailleurs, la même expression régulière est utilisée dans le frontend).

Bien qu'on sait maintenant comment passer cette validation, on risque d'avoir de la difficulté à effectuer une injection intéressante dans le fichier de configuration avec seulement des chiffres. Heureusement pour nous, il y a une coquille dans le code.

Dans la [documentation de Mozilla](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/test) pour la fonction `test()`, on peut lire:

> JavaScript RegExp objects are **stateful** when they have the global or sticky flags set (e.g., /foo/g or /foo/y). They store a lastIndex from the previous match. Using this internally, test() can be used to iterate over multiple matches in a string of text (with capture groups).

Puisque l'expression régulière de la liste noire possède le flag `g` (global), l'expression régulière est stateful. Concrètement, ceci veut dire que chaque appel de `test()` avec la même expression régulière sur la même chaine de caractères donnera un résultat différent, de manière séquentielle.

Voici un exemple:

```bash
$ node
Welcome to Node.js v24.6.0.
Type ".help" for more information.
> const exp = /[^\d]/g;
undefined
> exp.test('1a2b3')
true
> exp.test('1a2b3')
true
> exp.test('1a2b3')
false
```

La deuxième validation est donc inutile, il suffit de renvoyer la même requête plusieurs fois et lorsque tous les matchs auront été énumérés, la validation passera.

### `validateRoomKey`
Voici la fonction `validateRoomKey`:

```js
const ROOM_KEYS = new Map();

// ...

function validateRoomKey(roomCode, roomKey) {
    if(!ROOM_KEYS.has(roomCode)) return false;
    if(ROOM_KEYS.get(roomCode) != roomKey) return false;
    return true;
}
```

Cette fonction n'a pas de vulnérabilité évidente, elle vérifie que la valeur associée à `roomCode` dans `ROOM_KEYS` est égale à `roomKey` (si elle existe). Il faut donc trouver comment

Il existe déjà certaines clés de chambre par défaut, mais il faut qu'on puisse avoir une clé de chambre pour un code de chambre arbitraire, donc ce n'est pas très utile:

```js
/* seed data */
ROOM_KEYS.set('CBG:13' , '393391c8ed6194e1');
ROOM_KEYS.set('CBG:200', 'cbe32befb6599df6');
ROOM_KEYS.set('CBG:582', '209fbe997f83affc');
```

### `resetRoomKey`
En regardant ailleurs dans le code, on voit la fonction `resetRoomKey` qui réinitialise ou génère une nouvelle clé de chambre pour un code de chambre quelconque. Cette fonction est appelée directement par l'appel `POST /api/reset` sans aucune validation, donc on peut supposer qu'on peut l'appeler directement.

En voici le code:

```js
function resetRoomKey(roomCode) {
    const newRoomKey = toHexString(ENTROPY_POOL.getRandomBytes(8));
    ENTROPY_POOL.reseed();

    ROOM_KEYS.set(roomCode, newRoomKey);
}
```

À première vue, la fonction semble générer une séquence de 8 bytes aléatoires et produire une clé avec la séquence hexadécimale résultante. Bien sûr, ceci n'est vrai que si on assume que la séquence aléatoire et bel et bien aléatoire.

### `EntropyPool`
La classe `EntropyPool` est une classe spécifique au défi, en voici le code:

```js
const crypto = require('node:crypto');

class EntropyPool {
    constructor(size) {
        this.size = size;
        this.cursor = 0;
        this.reseed();
    }

    reseed() {
        this.buffer = crypto.randomBytes(this.size);
    }

    addEntropy(data) {
        for(let i = 0; i < data.length; i++) {
            this.buffer[this.cursor++ % this.size] = data[i];
        }
    }

    getRandomBytes(length) {
        const data = new Uint8Array(length);
        for(let i = 0; i < data.length; i++) {
            const sampled = this.buffer[Math.floor(Math.random() * this.buffer.length)];
            data[i] = sampled;
        }
        return data;
    }
}
```

La classe semble représenter un bassin de données aléatoires. La fonction `addEntropy` prend des données et les ajoute dans le `buffer` sous-jacent de manière circulaire. La fonction `getRandomBytes` elle sélectionne de manière aléatoire `length` bytes du `buffer` et les retourne.

Au moment de la construction de l'objet, le `buffer` est initialisé avec des données aléatoires correctes, par contre, dépendant de l'utilisation de `addEntropy`, ceci pourrait ne plus être vrai.

En effet, il existe un petit middleware dans l'application web qui ajoute de l'entropie:

```js
fastify.addHook('onRequest', async (req, _) => {
    const userAgent = req.headers['user-agent'] || '';
    const url = req.url || '';
    const body = req.body || '';

    const entropy = Buffer.from(`${Date.now()}${userAgent}${url}${body}`);
    ENTROPY_POOL.addEntropy(entropy);
});
```

Les données ajoutées sont une concaténation du temps en millisecondes, le `User-Agent` de la requête, l'URL de la requête et le corps de la requête. On peut constater que l'on contrôle entièrement le `User-Agent`, l'URL et le corps de la requête. On peut donc "empoisonner" le `EntropyPool` en la remplissant de données non-aléatoires, qui formeront ensuite notre clé de chambre.

Puisque ce middleware s'exécute avant la gestion de la requête, il serait approprié de faire notre empoisonnement dans la même requête qui réinitialise la clé de chambre. Par contre, ceci amène des inconvénients:

- La requête doit forcément avoir un URL qui pointe vers `/api/reset`, on perd un peu de contrôle.
- La requête doit forcément avoir un corps qui contient un objet JSON avec un `roomCode` pour la réinitialisation. On perd encore du contrôle.

Avec ces pertes de contrôle, on risque d'obtenir une clé taintée par des données qui seraient dûr à prédire.

Pour l'objet JSON, ce n'est au final pas un problème. En lisant la documentation de [Fastify](https://fastify.dev/docs/latest/Reference/Lifecycle/), on voit que le hook `onRequest` prend place avant le `preParsing`, le body n'existe donc pas à ce moment-ci. On peut se le convaincre en ajoutant un `console.log` si on veut.

Pour ce qui est de l'URL, puisque l'écriture est circulaire dans le `EntropyPool`, ce n'est pas un problème si on peut terminer notre URL avec assez de données contrôlées. Heureusement pour nous, l'URL inclue les paramètres de requête, donc on peut ajouter un argument du style `?throwaway=aaaaaaaaaaaaaaaa` à la fin de notre URL qui ne sera pas utilisé, mais qui empoisonnera le `EntropyPool`.

Pour récapituler, pour passer les deux validations, il faut:

1. Générer une clé de chambre connue pour un code de chambre voulu, ceci peut être fait en ajoutant un argument d'URL tel que `?throwaway=aaaaaa...` avec 256 caractères répétés (la taille du `EntropyPool`).
2. Envoyer N fois une requête à `POST /api/check` jusqu'à temps que l'expression régulière épuise les résultats.

Une fois fait, nous obtenons un contrôle presque total (sauf le préfixe `CBG:`) de la séquence qui est insérée dans le patron de configuration `template.cfg`.

### ripgrep
Maintenant qu'on a une injection dans le fichier de configuration, on peut se fier au manuel de ripgrep (voir `man rg`) et essayer d'assembler une injection qui va nous permettre de consulter les données dans `flag.txt`.

Ceci peut probablement être fait de plusieurs manières, mais une limitation est constante, nous sommes limités à 20 caractères contrôlées à cause de la validation API:

```js
    schema: {
        body: {
            type: 'object',
            required: ['roomCode', 'roomKey'],
            properties: {
                roomCode: {
                    type: 'string',
                    minLength: 4,
                    maxLength: 24 // < ici
                },
                roomKey: {
                    type: 'string',
                    minLength: 16,
                    maxLength: 16
                }
            }
        }
    }
```

Pour la solution officielle, le drapeau `-e` est utilisé pour spécifier un pattern vierge (puisque `CBG:` teint l'argument positionnel du pattern). Par contre, ça cause un nouveau problème:

> When -f/--file or -e/--regexp is used, then ripgrep treats all positional arguments as files or directories to search.

À cause de l'argument `-e`, `CBG:` devient un chemin de fichier/dossier et le code de retour est perpétuellement 2 à cause d'une erreur d'ouverture de fichier (le fichier `CBG:` n'existe pas).

Ce problème peut être contourné en utilisant l'argument `-q` (ou `--quiet`). En effet, on peut voir dans [le code de ripgrep](https://github.com/BurntSushi/ripgrep/blob/119a58a400ea948c2d2b0cd4ec58361e74478641/crates/core/main.rs#L94) que le fait d'utiliser `-q` rétabli le code de retour 0 en cas de match. On peut donc différentier un match par un `{"breached":true}` vs une erreur 401 au niveau du serveur web.

Pour spécifier le fichier `/flag.txt`, le spécifier complètement serait trop long, donc on peut utiliser le chemin de la racine `/` et filtrer par fichiers `*.txt` avec `-ttxt`. Ceci prend 7 caractères au lieu de 9 caractères.

Le code de chambre final a donc l'air de `CBG:\n-qe{pattern_de_4_caractères}\n-ttxt\n/`. On peut faire varier le pattern pour énumérer progressivement les caractères du flag.

Une solution automatisée se trouve [ici](./solve.py).

## Flag

`flag-0cdc46e7fc1fee49`
