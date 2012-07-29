/*
 * Test program for tivi interface
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <CtZrtpSession.h>
#include <CtZrtpCallback.h>
#include <ucommon/socket.h>

struct sockaddr_in adr_inet;
struct sockaddr_in adr_clnt;
socklen_t lenClnt;          // length
int s;                       // Socket

static void hexdump(const char* title, const unsigned char *s, int l)
{
    int n=0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n) {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x",n);
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}

//    V2 | PT  |   seqnum  |        timestamp      |          SSRC        |
uint8_t inviterPacket[] = {
    0x80, 0x03, 0x47, 0x11, 0x01, 0x01, 0x01, 0x01, 0xfe, 0xed, 0xba, 0xac,  // Header
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20};

uint8_t answererPacket[] = {
    0x80, 0x03, 0x08, 0x11, 0x02, 0x02, 0x02, 0x02, 0xba, 0xac, 0xed, 0xfe,  // Header
    0x20, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11};

uint8_t inviterPacket_fixed[] = {
    0x80, 0x03, 0x47, 0x11, 0x01, 0x01, 0x01, 0x01, 0xfe, 0xed, 0xba, 0xac,  // Header
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20};

uint8_t answererPacket_fixed[] = {
    0x80, 0x03, 0x08, 0x11, 0x02, 0x02, 0x02, 0x02, 0xba, 0xac, 0xed, 0xfe,  // Header
    0x20, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11};


int main(int argc,char **argv) {
    size_t invLength, answLength;
    char buffer[200];
    char invBuffer[200];
    char answBuffer[200];

    CtZrtpSession *inviter = new CtZrtpSession();
    inviter->init(true, true, "testzidSdes.dat");       // audio and video, name of cache file
    inviter->getSignalingHelloHash((char*)buffer, CtZrtpSession::AudioStream);
    fprintf(stderr, "Inviter Hello hash:  %s\n", buffer);

    CtZrtpSession *answerer = new CtZrtpSession();
    answerer->init(true, true, "testzidSdes.dat");       // audio and video, name of cache file
    answerer->getSignalingHelloHash((char*)buffer, CtZrtpSession::AudioStream);
    fprintf(stderr, "Answerer Hello hash: %s\n", buffer);

    invLength = sizeof(invBuffer);
    inviter->createSdes(invBuffer, &invLength, CtZrtpSession::AudioStream);
    printf("Inviter SDES security: length: %ld\n%s\n", invLength, invBuffer);

    // Virtually send the Inviter SDES crypto string to the answerer via SIP INVITE ........

    answLength = sizeof(answBuffer);
    // Set "sipInvite" parameter to false
    answerer->parseSdes(invBuffer, invLength, answBuffer, &answLength, false, CtZrtpSession::AudioStream);
    printf("Answerer SDES security: length: %ld\n%s\n", answLength, answBuffer);

    // Virtually send the answerer SDES crypto back to Inviter, via 200 OK probably

    // Set the "sipInvite" parameter to true
    inviter->parseSdes(answBuffer, answLength, NULL, NULL, true, CtZrtpSession::AudioStream);

    invLength = 0;
    inviter->processOutoingRtp(inviterPacket, sizeof(inviterPacket), &invLength, CtZrtpSession::AudioStream);
    hexdump("Inviter packet protected", inviterPacket, invLength);

    answLength = 0;
    answerer->processIncomingRtp(inviterPacket, invLength, &answLength, CtZrtpSession::AudioStream);
    hexdump("Inviter packet unprotected by answerer", inviterPacket, answLength);


    answLength = 0;
    answerer->processOutoingRtp(answererPacket, sizeof(answererPacket), &answLength, CtZrtpSession::AudioStream);
    hexdump("Answerer packet protected", answererPacket, answLength);

    invLength = 0;
    inviter->processIncomingRtp(answererPacket, answLength, &invLength, CtZrtpSession::AudioStream);
    hexdump("Answerer packet unprotected by inviter", answererPacket, invLength);
    return 0;
}













