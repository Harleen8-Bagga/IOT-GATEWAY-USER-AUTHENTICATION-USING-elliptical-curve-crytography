Login procedure between user and IOT

PWu  : password of user
Bu   : biometric user
IDu   :identity of user
HU   :Hash digest on h(PWu||Bu||Idu)
HU1  :Hash digest on h(PWU1||BU1||IDU1)
PWU1 :retrieved PWU value from storageC 
BU1   :retrieved BU value from storageC
IDU1  :retrieved BU1 value from storageC



IOT is the client and user is the server.


storageD text contains the hash digest value HU1 which was stored in the registration phase.

