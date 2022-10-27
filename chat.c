#define HASH_TABLE_SIZE 517
#define MAX_USERNAME_LENGTH 16
#define MAX_PENDING 5
#define SAVE_USERNAME 1
#define GET_UID 2
#define GET_USERLIST 3
#define LEAVE_SERVER 4
#define BROADCAST 5
#define LOGOUT 6
#define HT_ID 1000000000
#define MAX_BUFFER_LENGTH 1024 // Includes null char

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

struct msg
{
    long mtype;
    char mtext[MAX_BUFFER_LENGTH];
};

struct ctrl_msg
{
    long mtype;
    pid_t pid;
    char mtext[MAX_USERNAME_LENGTH];
};

struct ctrl_res_msg
{
    long mtype;
    int qid; // qid = 0 for failure, > 0 for success
};

struct hash_entry
{
    char user_name[MAX_USERNAME_LENGTH];
    int msgid;
    bool present;
    bool is_online;
};
char delim[] = " \t\r\n\v\f"; // POSIX whitespace characters
int msqid;
int ctrl_qid;
int ctrl_res_qid; // Control response qid
char self_username[MAX_USERNAME_LENGTH];
int self_uid; // self_uid = 0 if offline

void error_exit(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void send_error_msg(int clientfd, char *msg)
{
    int len = strlen(msg);
    if (send(clientfd, msg, len, 0) != len)
        error_exit("send error");
}

int calculate_hash(char *str)
{
    long long hash_value = 0;
    int n = strlen(str);
    const long long p = 37;
    const long long PRIME = 998244353;
    long long prime_pow = 1;
    for (int i = 0; i < n; i++)
    {
        hash_value = (hash_value + (str[i] * prime_pow) % PRIME) % PRIME;
        prime_pow = (prime_pow * p) % PRIME;
    }
    return hash_value % HASH_TABLE_SIZE;
}

int insert_table(char *username, struct hash_entry *hash_table)
{
    int len = strlen(username);
    for (int i = 0; i < len; i++)
    {
        if (username[i] == '\n')
        {
            username[i] = '\0';
            break;
        }
    }
    int hash_value = calculate_hash(username);
    int probe_no = 0;
    while (hash_table[hash_value].present == true && strcmp(username, hash_table[hash_value].user_name) != 0 && probe_no < HASH_TABLE_SIZE)
    {
        hash_value = (hash_value + 1) % HASH_TABLE_SIZE;
        probe_no++;
    }
    // Send Error message to msgq instead of printing
    if (strcmp(hash_table[hash_value].user_name, username) == 0)
    {
        // perror("Username already in use");
        if (hash_table[hash_value].is_online == false)
        {
            hash_table[hash_value].is_online = true;
            return hash_table[hash_value].msgid;
        }
        else
        {
            return 0;
        }
    }
    if (hash_table[hash_value].present == true)
    {
        // perror("Hash Table full, cannot insert\n");
        return 0;
    }
    hash_table[hash_value].present = true;
    strcpy(hash_table[hash_value].user_name, username);
    hash_table[hash_value].msgid = hash_value + 1;
    hash_table[hash_value].is_online = true;
    return hash_table[hash_value].msgid;
}

struct hash_entry *search_table(char *username, struct hash_entry *hash_table)
{
    int len = strlen(username);
    for (int i = 0; i < len; i++)
    {
        if (username[i] == '\n')
        {
            username[i] = '\0';
            break;
        }
    }
    int hash_value = calculate_hash(username);
    int probe_no = 0;
    while (hash_table[hash_value].present == true && probe_no < HASH_TABLE_SIZE)
    {
        if (strcmp(hash_table[hash_value].user_name, username) == 0)
        {
            return &hash_table[hash_value];
        }
        hash_value = (hash_value + 1) % HASH_TABLE_SIZE;
        probe_no++;
    }
    return NULL;
}

void handle_username()
{

    pid_t username_handler = fork();

    if (username_handler == -1)
    {
        error_exit("fork");
    }

    if (username_handler == 0)
    {
        struct hash_entry hash_table[HASH_TABLE_SIZE];
        memset(hash_table, 0, sizeof(hash_table));
        struct hash_entry *he;
        struct msg message;
        struct ctrl_msg req;
        struct ctrl_res_msg res;
        int bytes_read;
        while (1)
        {
            int nb = msgrcv(ctrl_qid, &req, sizeof(req) - sizeof(req.mtype), 0, 0);
            // printf("%ld %s\n", req.mtype, req.mtext);
            switch (req.mtype)
            {
            case SAVE_USERNAME:
                res.qid = insert_table(req.mtext, hash_table);
                res.mtype = req.pid;
                msgsnd(ctrl_res_qid, &res, sizeof(res.qid), 0);
                break;
            case GET_UID:
                he = search_table(req.mtext, hash_table);
                res.qid = (he == NULL ? 0 : he->msgid);
                res.mtype = req.pid;
                msgsnd(ctrl_res_qid, &res, sizeof(res.qid), 0);
                break;
            case GET_USERLIST:
                message.mtype = req.pid;
                int pos = 0;
                for (int i = 0; i < HASH_TABLE_SIZE; i++)
                {
                    if (hash_table[i].present == true)
                    {
                        strcpy(pos + message.mtext, hash_table[i].user_name);
                        pos += strlen(hash_table[i].user_name);
                        message.mtext[pos++] = ':';
                        if (hash_table[i].is_online == true)
                        {
                            strcpy(message.mtext + pos, " online\n");
                            pos += 8;
                        }
                        else
                        {
                            strcpy(message.mtext + pos, " offline\n");
                            pos += 9;
                        }
                    }
                }
                message.mtext[pos] = '\0';
                msgsnd(msqid, &message, strlen(message.mtext) + 1, 0);
                break;
            case LEAVE_SERVER:
                he = search_table(req.mtext, hash_table);
                res.mtype = req.pid;
                if (he == NULL)
                {
                    res.qid = 0;
                }
                else
                {
                    he->present = false;
                    he->user_name[0] = '\0';
                    res.qid = 1;
                }
                break;
            case BROADCAST:
                bytes_read = msgrcv(msqid, &message, sizeof(message) - sizeof(message.mtype), HT_ID, 0);
                printf("broadcasting: %d\n", bytes_read);
                for (int i = 0; i < HASH_TABLE_SIZE; i++)
                {
                    if (hash_table[i].present)
                    {
                        message.mtype = hash_table[i].msgid;
                        msgsnd(msqid, &message, bytes_read, 0);
                    }
                }
                break;
            case LOGOUT:
                he = search_table(req.mtext, hash_table);
                res.mtype = req.pid;
                if (he == NULL)
                {
                    res.qid = 0;
                }
                else
                {
                    he->is_online = false;
                    res.qid = 1;
                }
                break;
            default:
                break;
            }
        }
        exit(EXIT_FAILURE);
    }
}

int get_uid(char username[], int type)
{
    struct ctrl_msg un_msg;
    size_t un_size = strlen(username) + 1;
    un_msg.mtype = type;
    un_msg.pid = getpid();
    strcpy(un_msg.mtext, username);
    msgsnd(ctrl_qid, &un_msg, sizeof(un_msg) - sizeof(un_msg.mtype), 0);
    // printf("username before sending: %s, length: %d, bytes sent: %d\n", un_msg.mtext, strlen(un_msg.mtext), un_size + sizeof(un_msg.pid));
    struct ctrl_res_msg reply;
    msgrcv(ctrl_res_qid, &reply, sizeof(int), getpid(), 0);
    return reply.qid;
}

// check if the username is currently in use.
void login_client(int clientfd)
{
    char msg[] = "Enter Username (Max 15 characters):";
    self_uid = 0;
    while (!self_uid)
    {
        if (send(clientfd, msg, strlen(msg) + 1, 0) != strlen(msg) + 1)
            error_exit("send error");

        strcpy(msg, "Username taken. Try another one: "); // ensure strlen(msg) > second string
        // Receive username
        int name_len;
        if ((name_len = recv(clientfd, self_username, MAX_USERNAME_LENGTH - 1, 0)) < 0)
            error_exit("recv");
        self_username[name_len] = '\0';
        char *un_ptr = self_username;
        char *username = strtok_r(un_ptr, delim, &un_ptr);
        // Send username to process handling usernames
        self_uid = get_uid(username, SAVE_USERNAME);
    }

    strcpy(msg, "Logged in\n");
    send(clientfd, msg, strlen(msg) + 1, 0);
}

void send_msg(int clientfd, char *cmd, char *msg)
{
    if (!strlen(msg))
    {
        send_error_msg(clientfd, "Received empty message\n");
        return;
    }

    int uid = get_uid(cmd, GET_UID);
    if (!uid)
    {
        send_error_msg(clientfd, "Invalid username\n");
        return;
    }
    struct msg message;
    message.mtype = uid;
    strcpy(message.mtext, msg);
    msgsnd(msqid, &message, strlen(msg) + 1, 0);
}

void leave_server()
{
    int un_size = strlen(self_username);
    struct ctrl_msg msg;
    msg.mtype = LEAVE_SERVER;
    strcpy(msg.mtext, self_username);
    msgsnd(ctrl_qid, &msg, sizeof(msg) - sizeof(msg.mtype), 0);

    struct msg message;
    message.mtype = self_uid;
    msgsnd(msqid, &message, 0, 0);
    self_uid = 0;
}

void get_userlist(int clientfd)
{
    struct ctrl_msg message;
    message.mtype = GET_USERLIST;
    message.pid = self_uid;
    msgsnd(ctrl_qid, &message, sizeof(message.pid) + sizeof(message.mtext), 0);
}

void *read_mq(void *cfd)
{
    int clientfd = *(int *)cfd;
    struct msg msg;
    while (1)
    {
        memset(&msg, 0, sizeof(msg));
        int bytes_read = msgrcv(msqid, &msg, MAX_BUFFER_LENGTH, self_uid, 0);
        if (bytes_read == 0)
            break;
        printf("Received Broadcast: %s", msg.mtext);
        send(clientfd, msg.mtext, bytes_read, 0);
    }

    self_uid = 0;
}
void broadcast_ms(int clientfd, char *msg)
{
    if (strlen(msg) == 0)
    {
        send_error_msg(clientfd, "Empty message\n");
        return;
    }

    struct ctrl_msg ctrl_msg;
    ctrl_msg.mtype = BROADCAST;
    msgsnd(ctrl_qid, &ctrl_msg, sizeof(ctrl_msg.pid), 0); // Ask ht process to collect broadcast message

    struct msg main_msg;
    main_msg.mtype = HT_ID;
    strcpy(main_msg.mtext, msg);
    msgsnd(msqid, &main_msg, strlen(msg) + 1, 0);
}

void logout(int clientfd)
{
    struct ctrl_msg msg;
    msg.mtype = LOGOUT;
    strcpy(msg.mtext, self_username);
    msgsnd(ctrl_qid, &msg, sizeof(msg) - sizeof(msg.mtype), 0);

    struct msg message;
    message.mtype = self_uid;
    msgsnd(msqid, &message, 0, 0);
    self_uid = 0;
}

void process_client(int clientfd)
{
    login_client(clientfd);
    // Spawn a thread for relaying from message queue to socket
    pthread_t msq_t;
    if (pthread_create(&msq_t, NULL, read_mq, &clientfd) != 0)
    {
        error_exit("pthread");
    }

    char buf[MAX_BUFFER_LENGTH];
    int bytes_read;
    while (1)
    {
        if ((bytes_read = recv(clientfd, buf, MAX_BUFFER_LENGTH - 1, 0)) < 0)
        {
            error_exit("recv");
        }

        buf[bytes_read] = '\0';
        char *cmd, *msg = buf;
        cmd = strtok_r(msg, delim, &msg);
        if (bytes_read == 0 || strcmp(cmd, "logout") == 0)
        {
            logout(clientfd);
            pthread_join(msq_t, NULL);
            exit(EXIT_SUCCESS);
        }
        if (strcmp(cmd, "leave") == 0)
        {
            leave_server(clientfd);

            pthread_join(msq_t, NULL);
            exit(EXIT_SUCCESS);
        }
        else if (strcmp(cmd, "get_users") == 0)
        {
            get_userlist(clientfd);
        }
        else if (strcmp(cmd, "send") == 0)
        {
            cmd = strtok_r(msg, delim, &msg);
            send_msg(clientfd, cmd, msg);
        }
        else if (strcmp(cmd, "sendall") == 0)
        {
            broadcast_ms(clientfd, msg);
        }
        else
        {
            char msg[] = "Invalid Command\n";
            send_error_msg(clientfd, msg);
        }
    }
}

int main()
{

    msqid = msgget(IPC_PRIVATE, 0600);
    ctrl_qid = msgget(IPC_PRIVATE, 0600);
    ctrl_res_qid = msgget(IPC_PRIVATE, 0600);
    int serverSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
        error_exit("socket creation error");

    struct sockaddr_in serverAddress, clientAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(32340);
    serverAddress.sin_addr.s_addr = htons(INADDR_ANY);
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
        error_exit("bind error");

    if (listen(serverSocket, MAX_PENDING) == -1)
        error_exit("listen error");

    handle_username();
    for (int numConn = 0; numConn < HASH_TABLE_SIZE; numConn++)
    {
        int clientLength = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLength);
        if (clientSocket == -1)
            error_exit("client socket creation error");

        pid_t childpid;
        if ((childpid = fork()) > 0 || childpid == -1) // Close parent's client socket
        {
            close(clientSocket);
        }
        else
        {
            process_client(clientSocket);
        }
    }
}