# P2P Chat - Protocol

This folder contains the protocol definition and design documents.


## Description
Methods in the CRI protocol:

REGISTER, LOGIN, LOGOUT, HELLO, SEARCH, CHAT, TEXT, GROUP_CREATE, GROUP_SEARCH, GROUP_TEXT

Protocol packets start with a method identifier, written here as capitalized versions of the method names, and will be changed to identifier numbers (such as 01) in the protocol implementation.

All payload fields are seperated with `'\n'` (newline). Because of this, it is an illegal character in most fields.

A method will be replied with the same method, where possible, with extra information following the method identifier after a newline.

e.g.:
```
|--Client----------------------------------------Registry--|
|----o--->-->---LOGIN\nusername\npassword-->-->------o-----|
|----o---<--<--<--<----LOGIN\nOK-----<--<--<--<------o-----|
```
## Client
- Register
  - REGISTER\nusername\npassword
  - Username max. 16 characters
  - Passwrod max. ?? characters
- Login
  - LOGIN\nusername\npassword
- Logout
  - LOGOUT
- Send HELLO heartbeat every 60 seconds over UDP port.
  - HELLO\nusername
- Search for username
  - SEARCH\nusername
- Chat
  - Request: CHAT
  - Response: OK / REJECT | BUSY
  - TEXT\nusername\nMESSAGE (message max 325 characters)
- Group
  - GROUP_CREATE\nusername1\nusername2\nusername3 (max 100 users)
  - GROUP_SEARCH\ngroupid
  - GROUP_TEXT\ngroupid\nusername\nMESSAGE (message max 325 characters)
	
## Registry
- Register
  - REGISTER\nOK
    - If registration successful
  - REGISTER\nALREADY_EXISTS
    - If username already registered
  - All the usernames should be unique
- Login
  - LOGIN\nOK
    - If login successful
  - LOGIN\nFAIL
    - If login unsuccessful
  - Store the IP address of the user after login
- Logout
  - Remove the IP address of the user after logout
- Listen to UDP port for heartbeat
  - HELLO\nOK if everything ok
  - HELLO\nLOGOUT if registry forced logout due to inactivity or changed IP
  - Remove (Logout) after 200 seconds of no heartbeat
  - If IP and username don't match with the registry, the IP of the user has changed, Logout
- Search
  - SEARCH\nuserip
    - Return the IP if user is online
  - SEARCH\nOFFLINE
    - If user is offline
  - SEARCH\nNOT_FOUND
    - If username never registered
- Group
  - GROUP_CREATE
    - GROUP_CREATE\nMEMBERS_NOT_FOUND\nusername1\nusername2\nusername3
      - Return the usernames that couldn't be found.
  - GROUP_SEARCH
    - GROUP_SEARCH\nusername1\nIP1\nusername2\nIP2
      - Return an ordered list of username and IP addresses for all users of the group.
    - GROUP_SEARCH\nNOT_FOUND
      - Group with the given ID doesn't exist.
