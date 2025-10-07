### Type de pull request

- [ ] Nouveau défi simple.
- [ ] Nouvelle track de défis.
- [ ] Modification / fix à un défi existant.

### Type de déploiement

En plus de cocher le bon type de déploiement, ajoutez à votre pull request le bon label pour que le pipeline CI/CD fonctionne correctement.

- [ ] Aucun / Fichiers statiques à télécharger (mettre le label "aucun-déploiement").
- [ ] Déploiement unique pour tous les participants (mettre le label "déploiement-statique").
- [ ] Déploiement dynamique pour chaque participant (mettre le label "déploiement-dynamique").

### Vérifications générales

- [ ] Le dossier du défi suit l'arborescence `challenges/category/challenge-name/`.
- [ ] Le fichier `README.md` existe dans le dossier avec toutes les informations obligatoires.
- [ ] Le fichier `challenge.yml` existe dans le dossier avec toutes les informations obligatoires.
- [ ] Le fichier `solution.md` ou `solution/README.md` contient un write-up du défi. Si plusieurs fichiers sont nécessaires à la solution (ex. solveur automatisé), ils sont dans le dossier `solution`.
- [ ] Le flag est généré aléatoirement ou bien contient des caractères aléatoires afin de ne pas pouvoir être deviné (ex flag-y0u-f0und-1t-313aef90).
- [ ] Si le défi contient de nombreux fichiers, il est préférable de les placer dans un dossier `challenge` ou `src` pour facilement pouvoir consulter les metadata (`challenge.yml`, `README.md`, `compose.yaml`) sans se perdre.

### Vérifications pour track de défis (enlever si non applicable)

Cas 1 : Tous les défis sont dans le même dossier.

- [ ] Chaque défi est décrit par un fichier `challenge-x.yml` avec toutes les informations obligatoires.

Cas 2 : Chaque défi est dans un dossier séparé.

- [ ] Les dossiers des défis suivent l'arborescence `challenges/category/challenge-name/part-x/`.
- [ ] Chaque défi est décrit par un fichier `challenge.yml` avec toutes les informations obligatoires.
- [ ] Il y a soit un write-up par défi soit un write-up global dans `challenges/category/challenge-name/`.

### Vérifications pour déploiement statique ou dynamique (enlever si non applicable)

- [ ] Si nécessaire, un fichier `Dockerfile` pour construire une image Docker.
- [ ] Si nécessaire, un fichier `compose.yaml` qui décrit comment déployer l'image. Si ce fichier est manquant, le conteneur sera déployé sans paramètres supplémentaires et son port exposé sera accessible aux participants. Le fichier devrait suivre l'exemple dans `example-challenge/` pour son contenu.
