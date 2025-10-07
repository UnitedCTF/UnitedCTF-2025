# Part 1

Dans le code source, on a accès au username et au mot de passe de John, cependant, le username `john` est remplacé par rien lorsque le login form est soumis. Il suffit de mettre username : `jojohnhn` pour que suite au remplacement, le username soit `john` et on peut se logguer avec son mot de passe `johns_super_secret_password`

`flag-j0hn_h4s_b33n_f1r3d_r1p_1cf6bdb6`

# Part 2

Dans la page de statut des lumière, il y a une injection SQL sur l'id.L'utilisateur peut faire un script d'injection booléenne pour déterminer le mot de passe de l'admin. 

Si la lumière est `on` avec cette requête,  `' UNION SELECT 'on' from users where username = 'admin' and password like 'a%`, le caractère du mot de passe et bon et on passe au prochain.

`flag-4dm1n_p4ssw0rd_1s_n0t_4lw4ys_4dm1n_81326a25`

# Part 3

On peut exploiter ce bout de code dans la page administrateur.

```py
(scheme, host, path, query, fragment) = urllib.parse.urlsplit(url)

    # Validate that only the clock service can be called
    if host == "127.0.0.1:5123":
        [...]
    else:
        requestUrl = urllib.parse.urlunsplit(('', '', path, query, fragment))
```

On peut exploiter la fonction `urlsplit` en lui passant un payload comme celui-ci : `a:http://HOST`. Pour ce cas, le schema est `a` et le path est `http://HOST`. Lorsqu'on reconcatène l'url dans le else `urllib.parse.urlunsplit(('', '', path, query, fragment))`, le requestUrl résultant sera alors `http://HOST/clock`.

Par la suite, il suffit de rediriger la requête vers son propre serveur web qui retourne `12:00AM` sur le endpoint `/clock`.

`flag-s0us_l3_c13l_d3_p4r1s_l3s_lum13r3s_br1ll3nt_f4d1193e`