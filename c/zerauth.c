#define _GNU_SOURCE

#ifndef USERNAME
//# warning "No username specified"
# define USERNAME "000"
#endif

#ifndef PASSWORD
//# warning "No password specified"
# define PASSWORD "000"
#endif

#ifndef DOMAIN
# define DOMAIN "192.168.0.1"
#endif

#ifndef PORT
# define PORT 12080
#endif

#ifndef RENEW_DELAY
# define RENEW_DELAY 40
#endif

#ifndef TIMEOUT
# define TIMEOUT 10
#endif

#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

const char *g_authkey = NULL;

static int socket_connect(const char *host, int port, int timeout)
{
    struct hostent *hp;
    struct sockaddr_in addr;

    if ((hp = gethostbyname(host)) == NULL)
        return -1;

    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct timeval to;
    to.tv_sec = timeout;
    to.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(to));

    if (s == -1 ||
        connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
        return -1;

    return s;
}

static char *http(const char *host, int port,
                  const char* verb, const char* path, const char* data,
                  int timeout)
{
    char *content;
    if (data)
        asprintf(&content,
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %zu\r\n",
            strlen(data));
    else
        content = strdup("");

    char *to_send;
    asprintf(&to_send,
        "%s %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "%s\r\n%s", verb, path, host, content, data);

    free(content);

    int fd = socket_connect(host, port, timeout);
    if (fd == -1)
        return NULL;

    size_t i = 0;
    size_t l = strlen(to_send);
    while (i < l)
    {
        int k = send(fd, to_send + i, l - i, 0);
        if (k == -1)
            return NULL;
        i += k;
    }

    free(to_send);

    size_t size = 8192;
    char *result = malloc(size * sizeof (char));
    ssize_t received = 0;
    i = 0;
    while ((received = recv(fd, result + i, 1024, 0)) != 0)
    {
        if (received == -1)
        {
            free(result);
            result = NULL;
            break;
        }
        i += received;
        if (size - i < 1024)
        {
            size *= 2;
            result = realloc(result, size * sizeof (char));
        }
    }

    return result;
}

static char *portal_query(const char* section, const char* action,
                          const char* authkey)
{
    char *c;
    asprintf(&c,
            "U=%s&P=%s&Realm=%s&Action=%s&Section=%s&Authenticator=%s",
            USERNAME, PASSWORD, DOMAIN, action, section,
            authkey ? authkey : "");
    char *ret = http(DOMAIN, PORT, "POST", "/cgi-bin/zscp", c, TIMEOUT);
    free(c);
    return ret;
}

static char *get_authkey(const char* content)
{
    char *ret = malloc(64 * sizeof (char));
    const char *pos = strchr(strstr(content, "Authenticator"), '>') + 1;
    if (!pos)
    {
        free(ret);
        return NULL;
    }
    pos = strchr(pos, '>') + 1;
    for (int i = 0; pos[i] && pos[i] != '<'; i++)
        ret[i] = pos[i];
    return ret;
}

static void stop_callback()
{
    portal_query("CPGW", "Disconnect", g_authkey);
    exit(1);
}

static void signal_init(void)
{
    struct sigaction action;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    action.sa_handler = stop_callback;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}

int main(void)
{
    signal_init();
    char *content = NULL;
    char *authkey = NULL;
    while (1)
    {
        sleep(1);

        content = portal_query("CPAuth", "Authenticate", NULL);
        if (!content)
            goto socketerror;

        if (strstr("Access Denied", content))
        {
            fprintf(stderr, "Login failed, please check your login/password");
            goto fail;
        }

        authkey = get_authkey(content);
        if (!authkey)
        {
            fprintf(stderr, "Authkey not found.");
            goto fail;
        }
        g_authkey = authkey;

        if (!portal_query("CPGW", "Connect", authkey))
            goto socketerror;
        if (!portal_query("ClientCTRL", "Connect", authkey))
            goto socketerror;

        while (1)
        {
            int t = time(0);
            sleep(RENEW_DELAY);
            if (!portal_query("CPGW", "Renew", authkey))
                break;
            if (time(0) - t > (RENEW_DELAY * 3) / 2)
            {
                fprintf(stderr, "System has been suspended.");
                goto fail;
            }
        }

socketerror:
        fprintf(stderr, "Connection failed, retrying in 30s.");
fail:
        free(content);
        free(authkey);
        content = NULL;
        authkey = NULL;
        sleep(30);
    }
    return 0;
}
