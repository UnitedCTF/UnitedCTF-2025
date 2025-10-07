# Part 1

On remarque qu'il y a à la fois des messages utilisant le protocole UDP et des messages utilisant le protocole TCP, si on représente les paquets UDP par des 0 et les paquets TCP par des 1, on obtient `0110011001101100011000010110011100101101011011100011001101110111010111110111001101101000001100110110110001101100011100000110100000110000011011100011001101011111011101110110100000110000010111110110010000110001011100110101111100110111001100100110010101100100001101110110001100110110001110010011001001100011011001100011000001100101001110010011001100110011`

Lorsqu'on décrypte le binaire en ascii, on obtient le flag :

`flag-n3w_sh3llph0n3_wh0_d1s_72ed7c692cf0e933`

# Part 2

Chaque paquet contient un fragment d'une chaîne en base64, on peut utiliser scapy pour récupérer tous les fragments du base64.

```py
from scapy.all import rdpcap, Raw
import base64

data = b''.join(pkt[Raw].load for pkt in rdpcap('titan.pcapng') if Raw in pkt)
print(data.decode())
```

Ensuite on peut décoder le base64 pour avoir l'image suivante :

![flag2](atlantis.jpg)

L'image contient le flag :

`flag-h3ll0_fr0m_4tl4nt1s_6026ebea1436b1d4`

# Part 3

On a un petit indice dans la description du challenge, qui indique la lenteur des messages. En analysant les messages on remarque que certains sont envoyés rapidement après le précédent alors que d'autres prennent plus de temps. 

En faisant la différence entre les temps d'envoi des messages, on peut distinguer les messages qui prennent plus de 0.5 secondes avec ceux qui en prennent significativement moins. Si on représente les messages envoyés rapidement comme des 0 et ceux envoyés lentement comme des 1, on obtient la chaine :  `0110011001101100011000010110011100101101011110010011000001110101010111110011010001110010001100110101111100110100010111110111010001110010011101010011001101011111011100110110001101101000001100000110110000110100011100100101111101100110001100100011010001100110001110010110000100110110011000100011100000110110001110000011100101100110011000110110010000110111`

Lorsqu'on le décrypte, on obtient :

`flag-y0u_4r3_4_tru3_sch0l4r_f24f9a6b8689fcd7`