### Générateur de certificat SSL
##### Codé par Loïc GAVENS
<hr>

### Prérequis
- Python (3.9+)

### Installation
- Avoir venv et lancer `python3 -m venv venv` pour créer un environnement virtuel.
  - Il est impératif d'utiliser un environnement virtuel pour éviter les conflits de dépendances.
  - Lancer le venv avec `.\venv\Scripts\activate`.
- Installer les dépendances avec `pip install -r requirements.txt`.

### Utilisation
- Lancer le venv avec `.\venv\Scripts\activate`.
- Lancer le script avec `python3 main.py`.
- Suivre les résultats dans la console.

### Résultats

- Le certificat est généré dans le dossier `CA_ROOT_DEV` avec son arborescence.
- Pensez à sauvegarder le dossier `CA_ROOT_DEV` pour pouvoir générer de nouveaux certificats.

### Remerciements
- [Kilian-Pichard](https://github.com/Kilian-Pichard) pour la rédaction du rapport, la présentation et ses conseils.
- [Loïc B.]() pour son aide et ses conseils, son diagnostic et ses remarques.
- [Lilou B.]() pour la préparation du rapport et ses conseils et sa bonne humeur.


- [CY Tech](https://cytech.be/) pour m'avoir permis de réaliser ce projet.
- [OpenSSL](https://www.openssl.org/) pour son outil de génération de certificat.
- [Crypto](https://pypi.org/project/cryptography/) pour son outil de génération de certificat.
- [NGINX](https://www.nginx.com/) pour son serveur web et l'utilisation de certificats clients.


### Sources
- [StackOverflow](https://stackoverflow.com/)
- [Python](https://www.python.org/)
- [Visual Studio Code](https://code.visualstudio.com/)
- [GitHub](https://github.com/)