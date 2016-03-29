# PrivaNet
Partant d’un problème de violation de la vie privée constaté vers la fin de mes études d’ingénieur, une solution permettant de garantir, de donner et de protéger cette dernière fut étudiée.

PrivaNet est un projet qui a l’ambition de répondre aux problèmes de sécurité et de protection de la vie privée et au manque d’équité entre le prestataire d’un service dit Cloud et ses clients, grâce à un réseau pair à pair distribué structuré.

Ce logiciel a été développé à partir du code source de Overlay Weaver (http://overlayweaver.sourceforge.net/).
## Contexte
L’augmentation des terminaux informatiques et des objets connectés contrôlés par une même personne pousse à s’appuyer sur un stockage de données distant tel qu’un SaaS (Software as a Service), plus communément appelé Cloud.
Les facilités de cette utilisation ont créé une dépendance de ces services dans notre population.
## Problématique
La délégation de ces services peut infliger des problèmes de sécurité et de protection de la vie privée que les utilisateurs en soient conscient ou non.

La délégation de ces services peut infliger des problèmes de sécurité et de protection de la vie privée tel que :
* la sécurisation des contrôles d’accès,
* le chiffrement des données des utilisateurs,
* la garantie de confidentialité par le prestataire, voir par le(s) tiers, quand il y en a et
* le partage des données des utilisateurs avec des tiers (contre-exemple : Dropbox),

De plus, le prestataire de ces services centralisés se voit dans une position privilégiée : il peut procéder à de l’exploration des données de ses utilisateurs.
## Objectif
PrivaNet à l’ambition d'étudier comment donner le contrôle de leurs informations personnelles aux utilisateurs de services Cloud.

Pour ce faire, nous nous sommes concentrés sur le développement d’un service de stockage ne proposant pas un service unique, c’est-à-dire distribué sur l’ensemble des terminaux des utilisateurs.
Néanmoins, pour cela, il faut assurer de bonnes propriétés en terme d’utilisabilité, de performance, d'intégrité et de disponibilité des données.

PrivaNet se déploie sur un outil classique pour stocker et récupérer des informations sur un système distribué, en se détournant de services centralisés : la DHT !
Cet outil est potentiellement intéressant pour le développement d’un service Cloud distribué. Cependant, par défaut, les DHT n’incluent pas les fonctionnalités de sécurité précédemment citées (chiffrement,contrôle d’accès, etc.).

Le but du projet est donc de garantir, via une DHT, les propriétés de sécurité et de vie privée souhaitables, d’un service de stockage à distance, c’est-à-dire : l’authentification et le contrôle d’accès.
## Utilisation du code source
Ce code a été développé et testé à l'aide de Eclipse.
Pour utiliser ce code, vous devez créer un projet puis  importer les sources présentes dans le dossier src.
Pour finir, il faudra rajouter toutes les librairies Java présentes à la racine du dépôt.
## Exécution
Seul ow.tool.dhtshell.Main est testé et approuvé.
Par conséquent, utilisez cela pour faire vos manipulations.
