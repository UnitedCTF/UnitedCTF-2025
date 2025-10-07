### flag 1 : cypherpunks-Postcard

On nous fournis l'# de mint : 2uP4L2A1U4rCDJLZEgbnnoV6irEqgGcgnBi9KnJ6vNbb.

1. visualiser l'emplacement du mint sur la blockchain en utilisant metaplex explorer, il manque des configurations donc le NFT ne s'affiche pas directement sans viewer.
<img width="1461" height="683" alt="image" src="https://github.com/user-attachments/assets/ee1208bd-7897-4a4f-b44a-46b25c389513" />

3. Trouver le lien ipfs des metadata.
4. Ouvrir les metadata dans un visualisateur ipfs
<img width="1199" height="938" alt="image" src="https://github.com/user-attachments/assets/456eaee2-d938-4528-8092-f3a7ed694c07" />


5. Trouver le lien du NFT dans le json et visualiser le NFT.
<img width="1217" height="1187" alt="image" src="https://github.com/user-attachments/assets/c07feebb-918f-4cd7-9834-d754a8881f8a" />

7. Le flag est inscrit sur l'image.

lien ipfs :  bafybeibhbr4cwhrykh6muuc44eimku7qy6p7egmhz4pse3i362ueyctqqy

### flag 2 : cypherpunks-Visa

Ici on doit obtenir un visa qui consiste à interragir avec un smart contract. On nous fournie l'# du contrat on-chain directement dans le fichier get_visa.py.
Contrat : 2R2CMh6xqqS6Fe69pmTnaSsivSd2HSf4JKM7XGWNe8QN
<img width="1489" height="1107" alt="image" src="https://github.com/user-attachments/assets/43a542e0-d6ba-4a36-9058-f5baa9b82f10" />


1. Se créer un wallet solana et ajouter des SOL (snippet_kit/setup/create_ctf_wallet.sh).
2. Prendre connaissance de IDL.json
3. Demander son mint au serveur avec le fichier /snippet_kit/cypherpunks/mint_my_nft.py. Le contrat fait la vérification on chain.
4. Voir get_visa_sol.py pour la solution avec le contrat.
5. Le flag doit être réclamé une fois que le visa est délivré.
   
### flag 3 : cypherpunks-Border

Le flag 3 demande d'interragir avec le même contrat que le flag 2, mais cette fois-ci il faut demander de traverser la frontière. Nous fournissons l'# de l'account d'une personne ayant déjà passé la frontière.

1. Il faut regarder l'historique de la personne. Il faut posséder un visa.
3. On peut voir qu'une transaction suspecte a été fait à la gate 158 en échange d'une somme SOL. Le participant doit reproduire la transaction.
   <img width="1222" height="260" alt="image" src="https://github.com/user-attachments/assets/c7658233-0440-478e-9734-231325d021ca" />

5. Il pourra réutiliser la logique de communication présente dans get_visa.py, mais devra batir son propre programme selon l'idl.json. Voir pass_border_sol.py pour la solution.

### Réclamer le flag
Il faut faire rouler le programme get_flag.py fournie.
