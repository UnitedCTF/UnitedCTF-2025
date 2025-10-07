# Ami cloridormien discret

## Write-up

1. Regarder les communications lors d'une recherche, on reconnait le chemin /ldap et on voit les éléments d'une query LDAP.
2. On semble être en contrôle de deux côtés d'un filtre de recherche AND: la query exécutée sur le serveur nous est retournée lorsqu'on fait une requête avec des caractères invalides.
3. Le filtre anti astérisque est appliqué seulement du côté front-end, on peut le bypass avec burp et construire une requête telle que `lo=sn%3D*&ro=o%3D*`, ce qui nous retourne effectivement toutes les entrées. Une des entrées contient le flag, qui n'était pas initialement visible à cause que le frontend paramètre le filtre de droite comme `o=visible` initialement, ce qui empêche l'affichage des entrées ayant `o=hidden` dans le répertoire.

## EN

1. Looking at the communications during a search, we recognize the /ldap path and see the elements of an LDAP query.
2. We seem to be in control of both sides of an AND search filter: the query executed on the server is returned to us when we make a request with invalid characters.
3. The anti-special-chars filter is only applied on the front-end, so we can bypass it with burp and construct a query such as `lo=sn%3D*&ro=o%3D*`, which effectively returns all entries. One of the entries contains the flag, which was initially not visible because the frontend set the right-hand filter as `o=visible` initially, preventing the display of entries with `o=hidden` in the directory.


## Flag

`flag-th15_5h0uld_n0t_b3_s33n_923a12cd`
