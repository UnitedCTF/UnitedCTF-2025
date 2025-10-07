# How to cheat at tour guide questions 101

## Solution (French)

Ce challenge était basé sur le principe du "use after free". 
Un "use after free" arrive lorsqu'on utilise une variable après qu'elle soit libérée de la mémoire. 

Lorsqu'une variable est libérée avec "free", le pointer de cette variable redeviens disponnible pour la prochaine utilisation de "malloc", mais n'est pas détruite (la valeur existe encore!).

Ainsi, dans ce challenge, il était question d'utiliser le principe du "use-after-free" pour écrire par-dessus le nombre qui était à deviner. Lorsqu'on regarde la fonction "ask_question", on remarque que si nous répondont "0", il est possible de libérer la variable "question", ce qui nous permettrait de allocationner la notre variable "answer" directement à la même endroit dans la mémoire.

```
Are you ready for your final question? Everyone's looking! <enter>
```

Lorsqu'on répond "0" à la première question, la variable "question" est libérée et la variable "answer" est allocationnée à la même place dans la mémoire. Cela nous permet d'écrire la valeur de notre choix à la même place dans que "question.answer" la mémoire (les structures question_t and answer_t on la même structure).
```  
How many tourists came to <CITY/COUNTRY> only last year?
0
I'm curious, what would you have guessed?
512
```
Ensuite, il nous reste a deviner la même chose, car la variable "question" a été modifiée à cause d'un "use after free"
```
So close! I give you one last chance.
How many tourists came to <CITY/COUNTRY> only last year?
512
You win!
flag-us3_@fter_fr33_IsLiKer3T3llIngyOurFri3ndsJok3sL0ud3ry
```
