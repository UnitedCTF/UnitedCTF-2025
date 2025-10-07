# Solution challenge de Linux

Dans ce challenge, nous devons trouver un flag qui se cache dans une grande arboresence de dossiers. Malheureusement, les commandes find, grep, fgrep etc sont désactivées.

2 solutions s'offrent à vous. Vous pouvez soit automatiser à l'aide d'un script bash, soit y aller manuellement (avec vim, du globbing, ou d'autres astuces...)

Pour le script bash, voici un exemple : 

```
#!/bin/bash

search_for_flag() {
    local path=$1
    for dir in "$path"/*; do
        if [ -d "$dir" ]; then
            search_for_flag "$dir"
        elif [ -f "$dir" ] && [ "$(basename "$dir")" == "flag.txt" ]; then
            echo "Flag found at: $dir"
            awk '1' "$dir"
        fi
    done
}

base_path="longleat_maze"  # Adjust the path as needed
search_for_flag "$base_path"
```

Le script va chercher dans chaque dossier de l'arboresence et regarder s'il trouve un fichier flag.txt.