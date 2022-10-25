#define HASH_TABLE_SIZE 517
#define MAX_USERNAME_LENGTH 32
#define MAX_PENDING 5
#define SAVE_USERNAME 1
#define GET_UID 2
#define GET_USERLIST 3
#define LEAVE_SERVER 4
#define MAX_BUFFER_LENGTH 4096 // Includes null char
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

struct msg
{
    long mtype;
    char *mtext;
};

struct ctrl_msg
{
    long mtype;
    pid_t pid;
    char *mtext;
};

struct ctrl_res_msg
{
    long mtype;
    int qid; // qid = 0 for failure, > 0 for success
};

struct hash_entry
{
    char user_name[32];
    int msgid;
    bool present;
};

int msqid;
int ctrl_qid;
int ctrl_res_qid; // Control response qid

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

void insert_table(char *username, struct hash_entry *hash_table)
{
    int len = strlen(username);
    // for (int i = 0; i < len; i++)
    // {
    //     if (username[i] == '\n')
    //     {
    //         username[i] = '\0';
    //         break;
    //     }
    // }
    int hash_value = calculate_hash(username);
    int probe_no = 0;
    while (hash_table[hash_value].present == true && strcmp(username, hash_table[hash_value].user_name) != 0 && probe_no < HASH_TABLE_SIZE)
    {
        hash_value = (hash_value + 1) % HASH_TABLE_SIZE;
        probe_no++;
    }
    if (strcmp(hash_table[hash_value].user_name, username) == 0)
    {
        perror("Username already in use");
        return;
    }
    if (hash_table[hash_value].present == true)
    {
        perror("Hash Table full, cannot insert\n");
        return;
    }
    hash_table[hash_value].present = true;
    strcpy(hash_table[hash_value].user_name, username);
    hash_table[hash_value].msgid = hash_value;
}

int get_msgid(char *username, struct hash_entry *hash_table)
{
    int len = strlen(username);
    // for (int i = 0; i < len; i++)
    // {
    //     if (username[i] == '\n')
    //     {
    //         username[i] = '\0';
    //         break;
    //     }
    // }
    int hash_value = calculate_hash(username);
    int probe_no = 0;
    while (hash_table[hash_value].present == true && probe_no < HASH_TABLE_SIZE)
    {
        if (strcmp(hash_table[hash_value].user_name, username) == 0)
        {
            return hash_value;
        }
        hash_value = (hash_value + 1) % HASH_TABLE_SIZE;
        probe_no++;
    }
    return -1;
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
        while (1)
        {
        }
    }
}

int get_uid(char username[], int type)
{
    struct ctrl_msg un_msg;
    size_t un_size = strlen(username);
    un_msg.mtype = type;
    un_msg.pid = getpid();
    un_msg.mtext = malloc(un_size);
    if (un_msg.mtext == -1)
        error_exit("malloc");
    strcpy(un_msg.mtext, username);
    msgsnd(ctrl_qid, &un_msg, un_size + sizeof(un_msg.pid), 0);

    struct ctrl_res_msg reply;
    msgrcv(ctrl_res_qid, &reply, sizeof(int), getpid(), 0); // 1 character for indicating success or failure
    return reply.qid;
}

// check if the username is current in use.
void login_client(int clientfd)
{
    char msg[] = "Enter Username (Max 31 characters):";
    char self_username[MAX_USERNAME_LENGTH];
    bool logged_in = false;
    while (!logged_in)
    {
        if (send(clientfd, msg, strlen(msg), 0) != strlen(msg))
            error_exit("send error");

        strcpy(msg, "Username taken. Try another one: "); // ensure strlen(msg) > second string
        // Receive username
        int name_len;
        if ((name_len = recv(clientfd, self_username, MAX_USERNAME_LENGTH - 1, 0)) < 0)
            error_exit("recv");
        self_username[name_len] = '\0';

        // Send username to process handling usernames
        logged_in = get_uid(self_username, SAVE_USERNAME);
    }
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
    message.mtext = msg;
    msgsnd(msqid, &message, strlen(msg), 0);
}

void process_client(int clientfd)
{
    login_client(clientfd);
    char buf[MAX_BUFFER_LENGTH];
    char delim[] = " \t\r\n\v\f"; // POSIX whitespace characters
    int bytes_read;
    while (1)
    {
        if ((bytes_read = recv(clientfd, buf, MAX_BUFFER_LENGTH - 1, 0)) < 0)
            error_exit("recv");

        buf[bytes_read] = '\0';
        char *cmd, *msg = buf;
        cmd = strtok_r(msg, delim, &msg);
        if (strcmp(cmd, "leave") == 0)
        {
            // TODO
            leave_server(clientfd);
        }
        else if (strcmp(cmd, "get_users") == 0)
        {
            // TODO
            get_userlist();
        }
        else if (strcmp(cmd, "send") == 0)
        {
            cmd = strtok_r(msg, delim, &msg);
            send_msg(clientfd, cmd, msg);
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