# npchatter
TCP based chat server implemented for the course IS_F462 Network Programming at BITS Pilani

## Run
```
    gcc -o chat chat.c -pthread
    
    ./chat

    telnet 127.0.0.1 <port>
```

## Features / Commands implemented

- Login/Join and Logout  
User is logged in with entered username if no other client with same user name is online. If this username is used for the first time, a new profile is created. 

```
    logout
```

- Individual messaging  
Send a message to any specific user, either online or offline
```
    send <username> <message>
    send pranjal hi! Harsh this side
```

- Broadcasting  
Send message to all users.
```
    sendall This is an example of a broadcast message
```

- Get list of all registered users, offline or online along with last seen information
```
    get_users
```

- Block and unblock upto 10 users
```
    block pranjal
    unblock pranjal
```

- Leave the chat server
```
    leave
```

## Assumptions

For simplicity, following assumptions have been made

- Maximum number of registered users is 517
- Maximum length of username is 15 with no whitespace 
- Maximum length of a message is 1005 characters

## Design Features

A total of three message queues have been used.  
- Queue 1 is for sending the messages from one user to another. Each user is alloted a unique integer identifier using which it retrieves message from queue 1  
- Queue 2 is used for sending control messages to the process maintaining a hash table which sends back messages on Queue 3. All messages sent on queue 2 are received by the hashtable process.  
- Queue 3 is used for sending back replies to control messages. Message type is pid of the recipient process 
### Joining and Leaving the server or logging out

- When the user connects to the server, they are asked for a username. It is checked if any other client with same username is online and if not the current user is marked online. If a fresh username is provided, a new entry is created. 
- Information for each user is managed by a common process which maintains a hashtable storing users' info. Each fresh username is provided a unique integer identifier.
- If a user disconnects, it is marked offline and the corresponding child process exits. If a user issues the command `leave`, the user entry is marked as deleted in the hashtable.

### Obtaining list of users with status

- When a user issues the command `get_users`, a control message is sent to the hashtable process by the child handling the corresponding user. 
- The hashtable process iterates over the hashtable and creates a list of users with status. This list is sent on Queue 1.
- This list is received by the client's child and sent to the user.

### Sending messages
- For each individual message, user id of the receiver process is requested from the hashtable process (received on queue 3). Sender process sends a message on queue 1 with message type = user id.
- For broadcast message, the entire message is sent to the hashtable process. This process sends one message on queue 1 for each registered user. 

### Communication between child process and about TCP connection
- For each new connection, a new child process is created. Child processes use message queues for communicating among each other. Each child spawns a thread for reading the message queue. So, the main thread waits on socket and the second threads waits on message queue.
### Additional Features

#### Last Seen
- For offline users, last seen information is maintained in the hashtable.
- This can be viewed using `get_users` command.

#### Temporarily block users
- Upto 10 users can be blocked. 
- Maintained a list of blocked user. Message sent to a blocked user are permanently lost.

## Screenshots

![Connecting to the server](./screenshots/connecting.jpeg?raw=true)
*Connecting to the server*

&nbsp;

![Get List of users](./screenshots/get_user_list.png?raw=true)
*Get List of users*

&nbsp;
![Sending a message](./screenshots/send_msg.png?raw=true)
*Sending a message*

&nbsp;
![Broadcasting a message](./screenshots/broadcast.png?raw=true)
*Broadcasting a message*

&nbsp;
![Blocking user](./screenshots/block.png?raw=true)
*Blocking users*