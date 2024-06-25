# secure_messaging

## Authentication 

Based on PKCS 1 version 2.2

### Authentication process

- Server : send "Start auth"
- Client : send id and rsa public challenge key 
- Server : create challenge based on client rsa key and send it
- Client : compute the challenge and send the response
- Server : test the response and send its rsa public challenge key
- Client : create challenge based on server rsa key and send it
- Server : compute the challenge and send the response
- Client : test the response and send its rsa public encryption key 
- Server : write in the db the keys of the client and senf its rsa public encryption key
- Client : send its signature symmetric key
- Server : send its signature symmetric key
- Client : send its encryption symmetric key
- Server : send its encryption symmetric key
- Client : update sessions information
- Server : update sessions information

## To-do

- A FAIRE VITE : Côté client et serveur, rajouter le chiffrement asymétrique lors de l'envoie des clés symmétriques
- Faire système de gestion des erreurs
- Faire une petite interface utilisateur
- Faire implémentation aes-256
- Faire implémentation hmac-512
- Faire base de données enregistrement des messages de façon sécurisée (une côté serveur pour la sauvegarde des messages et une du côté client)
- Faire un système permettant de skip l'échange de clés rsa en les stockant et en les cherchant dans la db_id
- Faire un système pour pouvoir changer de clés rsa au niveau du client (rajouter une couche de sécurité comme redemander les clés précédentes ou un système de certificat)

