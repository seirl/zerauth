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
        "Host: 192.168.0.1:12080\r\n"
        "Connection: keep-alive\r\n"
        "User-Agent: Mozilla/5.0 (Android; Mobile; rv:33.0) Gecko/33.0 Firefox/33.0\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: fr,fr-fr;q=0.8,en-us;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Referer: http://192.168.0.1:12080/cgi-bin/zscp?Section=CPAuth&Action=Show&ZSCPRedirect=time.is:::http://time.is/%%3f\r\n"
        "%s\r\n%s", verb, path, content, data);

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
    if (authkey)
        asprintf(&c,
                "U=%s&P=%s&Realm=arpej.com&Action=%s&Section=%s&Authenticator=%s&ZSCPRedirect=_:::_",
                USERNAME, PASSWORD, action, section,
                authkey);
    else
        asprintf(&c,
                "U=%s&P=%s&Realm=arpej.com&Action=%s&Section=%s&ZSCPRedirect=_:::_",
                USERNAME, PASSWORD, action, section);

    char *ret = http(DOMAIN, PORT, "POST", "/cgi-bin/zscp", c, TIMEOUT);
    free(c);
    return ret;
}

static char *get_authkey(const char* content)
{
    char *ret = malloc(128 * sizeof (char));
    const char *pos = strchr(strstr(content, "Authenticator"), '"') + 1;
    if (!pos)
    {
        free(ret);
        return NULL;
    }

    int j = 0;
    int i = 0;
    // 125 is buffer size minus 1 for '\0' and 2 for extra char that come in %xx
    for (; j < 125 && pos[i] && pos[i] != '"'; ++i, ++j)
    {
        if (pos[i] == '/')
        {
            ret[j++] = '%';
            ret[j++] = '2';
            ret[j] = 'F';
        }
        else if (pos[i] == '+')
        {
            ret[j++] = '%';
            ret[j++] = '2';
            ret[j] = 'B';
        }
        else if (pos[i] == '\n')
        {
            ret[j++] = '%';
            ret[j++] = '0';
            ret[j] = 'A';
        }
        else if (pos[i] == '=')
        {
            ret[j++] = '%';
            ret[j++] = '3';
            ret[j] = 'D';
        }
        else
            ret[j] = pos[i];
    }
    ret[j] = '\0';
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

        if (strstr(content, "Access Denied"))
        {
            fputs("Login failed, please check your login/password.", stderr);
            goto fail;
        }

        authkey = get_authkey(content);
        if (!authkey)
        {
            fputs("Authkey not found.", stderr);
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
                fputs("System has been suspended.", stderr);
                goto fail;
            }
        }

socketerror:
        fputs("Connection failed, retrying in 30s.", stderr);
fail:
        free(content);
        free(authkey);
        content = NULL;
        authkey = NULL;
        sleep(30);
    }
    return 0;
}
