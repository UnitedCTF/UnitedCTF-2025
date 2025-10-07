# Les animaux de Cloridorme

## Write-up

1. Regarder les communications lors d'une recherche, on reconnait le chemin /ldap et on voit les éléments d'une query LDAP.
2. Puisque l'administrateur n'apparaît pas avec les OU users et pets, on peut penser à faire une recherche un niveau plus haut. Pour cela il faut se débarasser de la section OU du DN, et on peut le faire si OU est vide. Toutefois le code vérifie si c'est vide, mais ne vérifie pas si on met `%20` comme valeur pour OU dans la requête. On se retrouve alors à faire une recherche avec le DN `dc=cloridorme,dc=unitedctf``
3. Puisque toutes les entrées observées jusqu'ici contiennent la propriété `objectClass: inetOrgPerson` et qu'on contrôle le filtre SN, on peut demander à appliquer le filtre `objectClass%3DinetOrgPerson` pour voir toutes les inetOrgPerson du répertoire LDAP, indépendamment de leur OU d'appartenance.
4. Le flag est dans la description du compte grenouilleadmin.

## EN

1. Looking at the communications during a search, we recognize the /ldap path and see the elements of an LDAP query.
2. Since the administrator doesn't appear with the users and pets OUs, we can think of doing a search at a higher level. To do this, you need to get rid of the OU section of the DN, which you can do if OU is empty. However, the code checks if it's empty, but doesn't check if you put `%20` as the value for OU in the query. This results in a search with the DN `dc=cloridorme,dc=unitedctf``.
3. Since all the entries observed so far contain the property `objectClass: inetOrgPerson` and we control the SN filter, we can ask to apply the `objectClass%3DinetOrgPerson` filter to see all the inetOrgPerson in the LDAP directory, regardless of which OU they belong to.
4. The flag is in the description of the frogadmin account.


## Flag

`flag-ar3nt_th3y_cut3z_1acca02ed`
