# Directives de contribution

## Pour commencer
- Faites un fork du répertoire pour travailler sur votre défi.

## Organisation & requis
- Les défis devraient être créés sous l'arborescence `challenges/<catégorie>/<nom du défi>` avec les noms de dossiers en kebab case (soit `[a-z-]+`, lettres minuscules et tirets).
- En cas de doute, ne pas hésiter à copier le défi `example-challenge` puis garder ce qui est pertinent et enlever le reste.
- Chaque défi devrait contenir:
    - Un README.md avec le nom de l'auteur, une description en français et en anglais, sans oublier le flag (faites un double-check pour s'assurer qu'il est identique).
    - Un fichier `challenge.yml` contenant des détails sur le défi selon la [spécification ctfcli](https://github.com/CTFd/ctfcli/blob/master/ctfcli/spec/challenge-example.yml). Pas besoin de tout remplir, il faut seulement:
        - name
        - author
        - category
        - description (en + fr)
        - type
            - "standard" (valeur fixe)
        - value
            - score fixe estimé selon la norme [CFSS](https://github.com/res260/cfss)
            - c'est pas grave si c'est pas exact, ça va être validé au QA, mais laissez un commentaire à côté de l'estimation avec les critères CFSS
        - flag(s)
        - tags
        - files (si applicable)
        - hints (si applicable)
        - requirements (si le challenge suit un autre)
    - Un document similaire au README pour décrire votre solution avec des étapes. Si la solution peut être automatisée, un script de vérification automatique serait grandement apprécié. Ce document devrait être nommé `solution.md` ou être dans `solution/README.md`.
    - Si le challenge nécessite un déploiement:
        - Un `Dockerfile` pour le défi avec une directive `EXPOSE` pour clairement identifier le port qui doit être exposé par l'infrastructure. Si le challenge nécessite plusieurs conteneurs ou une configuration spécifique, fournissez un `compose.yaml` avec les services nécessaires (voir `exemple-challenge` pour une base à modifier).

## Sanity checks
- Est-ce que vous avez réussi à résoudre votre propre challenge?
- Est-ce que quelqu'un qui n'a pas designé le challenge serait capable de tirer les conclusions nécessaires à la complétion du challenge?
- Est-ce que votre challenge est le fun ou intéressant? S'il nécessite beaucoup de temps, est-ce par nécessité et est-ce raisonnable?
- Est-ce que la solution de votre challenge dépend d'un langage, d'une librairie ou d'une version spécifique d'une librairie/d'un framework? Si oui, assurez-vous que ça soit indiqué explicitement _ou implicitement_.
- Si votre challenge est mutable, assurez-vous que les actions d'un joueur ne puissent pas impacter négativement un autre joueur (ou leaker la solution).
    - Dans le cas où le défi est mutable et qu'il n'est pas possible de bien isoler les actions de chaque joueur, spécifiez que votre challenge nécessite des instances individuelles au moment de la pull request.

## Au moment de la pull request...
- Créez votre pull request vers la branche `main` du répertoire principal.
- Si votre défi a des besoins particuliers (accès à l'internet, **instances individuelles par joueur**, bot discord, réseaux virtuels, etc.), veuillez les spécifier. Si vous avez des besoins _très_ particuliers, contactez `@romai_n` sur Discord pour voir si c'est faisable.
- Annoncez que votre challenge est prêt au QA dans le canal de communication `#qa` sur Discord.
- Suivez votre pull request au cas où il y aurait des choses à changer ou des questions lors du QA (cette communication peut se faire sur Discord selon vos préférences).
- Attention de ne pas fusionner la pull request vous-même, certaines validations doivent être faites du côté du QA et de l'infrastructure.

