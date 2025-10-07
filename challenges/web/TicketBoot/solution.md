# Part 1

Dans la source de la page, on trouve une référence vers le endpoint `/actuator`. 
En explorant les endpoints de l'actuator, on trouve le endpoint `/actuator/env` qui renseigne les variables
d'environnement de l'application. Dans les variables d'environnement, on retrouve le premier flag.

`flag-w3lc0m3_t0_th3_t1ck3t_b00t_e058b670`

# Part 2

En explorant plus l'actuator, dans `/actuator/mappings`, on trouve de la documentation openAPI sous l'endpoint `/v3/api-docs`.
Dans la documentation, il est indiqué que les opérations POST et GET sur /ticket créent et lisent les tickets dans le répertoire
`/tickets/{id}`. Pour le GET, l'id est un paramètre spécifié par l'utilisateur.

Dans `/actuator/beans`, on retrouve les différents beans utilisés par l'application Springboot. Dans les beans il y a différentes
classes de l'application. On y retrouve notamment la class `TicketController` avec le chemin du fichier compilé 
`/app/classes/com/united/TicketBoot/ticket/TicketController.class`.

On peut ensuite utiliser le path traversal dans lecture de tickets pour inclure les fichiers .class. Il suffit d'enlever la validation fait en front end 
ou en naviguer directement vers le endpoint `/ticket?ticketId=../app/classes/com/united/TicketBoot/ticket/TicketController.class`. 
Il est possible de décompiler l'hexadecimal du fichier .class pour avoir la source ou simplement lire le texte brute pour trouver 
le code promo `FREE_CRUISE_TICKETS_a0e5fce92e91b0d1ba55dcc10732d85d`.

En créant un ticket avec le code promo et en le lisant avec l'id généré, on obtient le flag.

`flag-c0ngr4tul4t10ns_h3r3_1s_y0ur_cru1s3_t1ck3t!!_feccc248`

# Part 3

En utilisant la même technique pour lire les fichiers compilés, on peut lire le fichier `FirstClassTicketService.class`.
En analysant la classe, on voit la méthode `getFlag`, qui requiert le mot de passe `ticketboot.superSecretPassword`.
Cependant, on voit qu'il n'y a aucun appel explicite vers la méthode `getFlag`. En observant un peu le code source, on voit
que l'application utilise l'engin de templating thymeleaf pour générer les pages html.

Dans les fichiers html, un commentaire indique l'emplacement du fichier. On peut lire le fichier `/app/resources/templates/index.html`
Dans `index.html`, on voit qu'il y a un SSTI possible dans le champ `nom`.

En utilisant le code promo, on peut créer un billet avec le nom `${@environment.getProperty('ticketboot.superSecretPassword')}`.
On obtient le mot de passe secret : `FIRST_CLASS_TICKETS_ca3e24ded9af48c01df28c830f192f95`. Ensuite, il suffit de réutiliser
le SSTI pour faire appel à getFlag avec le mot de passe : `${@firstClassTicketService.getFlag('FIRST_CLASS_TICKETS_ca3e24ded9af48c01df28c830f192f95')}`
pour obtenir le dernier flag.

`flag-f1r5t_cl4s5_thym3_t0_p4rtyyy!!!?!_4a50fb71`