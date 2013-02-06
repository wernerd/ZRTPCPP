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

#include <CtZrtpSession.h>
#include <CtZrtpCallback.h>
#include <libzrtpcpp/ZrtpSdesStream.h>


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


// This is the callback that we use for audio stream
class TestCallbackAudio: public CtZrtpCb {
    void onNewZrtpStatus(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) {
        fprintf(stderr, "new status: %s\n", p == NULL ? "NULL" : p);
        if (session->isSecure(streamNm)) {
            uint8_t buffer[20];

            session->getInfo("rs1", buffer, 9);
            printf("RS1: %s ", buffer);

            session->getInfo("rs2", buffer, 9);
            printf("RS2: %s ", buffer);

            session->getInfo("pbx", buffer, 9);
            printf("PBX: %s ", buffer);

            session->getInfo("aux", buffer, 9);
            printf("AUX: %s\n", buffer);

            session->getInfo("lbClient", buffer, 19);
            printf("Client: %s ", buffer);

            session->getInfo("lbVersion", buffer, 19);
            printf("Version: %s ", buffer);

            session->getInfo("lbChiper", buffer, 19);
            printf("cipher: %s ", buffer);

            session->getInfo("lbHash", buffer, 19);
            printf("hash: %s ", buffer);

            session->getInfo("lbAuthTag", buffer, 19);
            printf("auth: %s ", buffer);

            session->getInfo("lbKeyExchange", buffer, 19);
            printf("KeyEx: %s\n", buffer);

        }
    }

    void onNeedEnroll(CtZrtpSession *session, CtZrtpSession::streamName streamNm, int32_t info) {
        fprintf(stderr, "Need enroll\n");
    }

    void onPeer(CtZrtpSession *session, char *name, int iIsVerified, CtZrtpSession::streamName streamNm) {
        fprintf(stderr, "onPeer: %s\n", name == NULL ? "NULL" : name);
    }

    void onZrtpWarning(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) {
        fprintf(stderr, "Warning: %s\n", p == NULL ? "NULL" : p);
    }

};

class TestSendCallbackAudio: public CtZrtpSendCb {
    void sendRtp(CtZrtpSession const *session, uint8_t* packet, size_t length, CtZrtpSession::streamName streamNm) {
//        hexdump("ZRTP packet", packet, length);
        fprintf(stderr, "ZRTP send packet, length: %lu\n", length);
    }
};

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

    char invMixBuffer[200];
    char answMixBuffer[200];

//     ZrtpSdesStream sdes;
// 
//     fprintf(stderr, "Get mix: %d ", sdes.getCryptoMixAttribute(buffer, 200));
//     fprintf(stderr, "Get mix: %s\n", buffer);
// 
//     fprintf(stderr, "Empty: %d\n", sdes.setCryptoMixAttribute(""));
//     fprintf(stderr, "Only one valid: %d\n", sdes.setCryptoMixAttribute("HMAC-SHA-384"));
//     fprintf(stderr, "Invalid valid: %d\n", sdes.setCryptoMixAttribute("BABAB HMAC-SHA-384"));
//     fprintf(stderr, "Invalid: %d\n", sdes.setCryptoMixAttribute("BABAB"));
//     fprintf(stderr, "Invalid valid: %d\n", sdes.setCryptoMixAttribute("BABAB HMAC-SHA-384"));
// 
//     fprintf(stderr, "Get mix: %d ", sdes.getCryptoMixAttribute(buffer, 200));
//     fprintf(stderr, "Get mix: %s\n", buffer);

    TestCallbackAudio *callback = new TestCallbackAudio();
    TestSendCallbackAudio *sendCallback = new TestSendCallbackAudio();

    CtZrtpSession::initCache("testzidSdes.dat");        // initialize global cache file

    // The Inviter session (offerer)
    CtZrtpSession *inviter = new CtZrtpSession();
    inviter->init(true, true);                          // audio and video
    inviter->setUserCallback(callback, CtZrtpSession::AudioStream);
    inviter->setSendCallback(sendCallback, CtZrtpSession::AudioStream);

    // The answerer session
    CtZrtpSession *answerer = new CtZrtpSession();
    answerer->init(true, true);                         // audio and video
    answerer->setSendCallback(sendCallback, CtZrtpSession::AudioStream);

    // Inviter first step: create a SDES crypto string
    invLength = sizeof(invBuffer);
    inviter->createSdes(invBuffer, &invLength, CtZrtpSession::AudioStream);
    if (invLength != 73) {
        fprintf(stderr, "Inviter - Answerer - SDES crypto string wrong size: got: %d, expected: 73\n%s\n", (int)invLength, invBuffer);
        return 1;
    }
    // Inviter second step: Get all available SDES crypto mix algorithms as nul terminated string
    int invMixLength = sizeof(invMixBuffer);
    invMixLength = inviter->getCryptoMixAttribute(invMixBuffer, invMixLength, CtZrtpSession::AudioStream);
    if (invMixLength == 0) {
        fprintf(stderr, "Inviter: SDES crypto mixer algorithm returned zero\n");
        return 1;
    }
    fprintf(stderr, "Inviter mixer algos: %s\n", invMixBuffer);

    // ****
    //  Now send the Inviter SDES crypto string and the mixer algo string to the answerer via SIP INVITE ........
    // ****

    // answerer first step: set the crypto mix algorithms, the answerer selects one of it
    answerer->setCryptoMixAttribute(invMixBuffer, CtZrtpSession::AudioStream);

    // answerer second step: get the seleted crypto mixer algorithm
    int answMixLength = sizeof(answMixBuffer);
    answMixLength = answerer->getCryptoMixAttribute(answMixBuffer, answMixLength, CtZrtpSession::AudioStream);
    if (answMixLength == 0) {
        fprintf(stderr, "Answerer: SDES crypto mixer algorithm returned zero\n");
        return 1;
    }
    fprintf(stderr, "Answerer selected mixer algos: %s\n", answMixBuffer);

   // answerer third step: parse the SDES crypto string and the answere SDES creates onw crypto string
    answLength = sizeof(answBuffer);
    answerer->parseSdes(invBuffer, invLength, NULL, NULL, false, CtZrtpSession::AudioStream);

    // answerer fourth step: get the generated SDES crypto string
    answerer->getSavedSdes(answBuffer, &answLength, CtZrtpSession::AudioStream);
    if (answLength != 73) {
        fprintf(stderr, "Error - Answerer - SDES crypto string wrong size: got: %d, expected: 73\n%s\n", (int)answLength, answBuffer);
        return 1;
    }

    // Send the answerer SDES crypto string and crypto mixer algorithms back to Inviter, via 200 OK probably

    // Inviter third step: set the received (it's one only) crypto mix algorithm
    inviter->setCryptoMixAttribute(answMixBuffer, CtZrtpSession::AudioStream);

    // Inviter fourth step: parses answerer's string, sets the "sipInvite" parameter to true
    inviter->parseSdes(answBuffer, answLength, NULL, NULL, true, CtZrtpSession::AudioStream);
    inviter->start(0xfeedbac, CtZrtpSession::AudioStream);


    invLength = 0;
    inviter->processOutoingRtp(inviterPacket, sizeof(inviterPacket), &invLength, CtZrtpSession::AudioStream);
//    hexdump("Inviter packet protected", inviterPacket, invLength);

    answLength = 0;
    answerer->processIncomingRtp(inviterPacket, invLength, &answLength, CtZrtpSession::AudioStream);
    if (memcmp(inviterPacket, inviterPacket_fixed, answLength) != 0) {
        hexdump("Error - Inviter packet unprotected by answerer", inviterPacket, answLength);
        return 1;
    }

    answLength = 0;
    answerer->processOutoingRtp(answererPacket, sizeof(answererPacket), &answLength, CtZrtpSession::AudioStream);
//    hexdump("Answerer packet protected", answererPacket, answLength);

    invLength = 0;
    inviter->processIncomingRtp(answererPacket, answLength, &invLength, CtZrtpSession::AudioStream);
    if (memcmp(answererPacket, answererPacket_fixed, invLength) != 0) {
        hexdump("Error - Answerer packet unprotected by inviter", answererPacket, invLength);
        return 1;
    }
    printf("PASSED\n");
    return 0;
}












