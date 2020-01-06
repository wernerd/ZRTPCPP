//
// Created by wdi on 04.01.20.
//

#include <cinttypes>

#include "../clients/tivi/CtZrtpSession.h"
#include "../clients/tivi/CtZrtpCallback.h"
#include <libzrtpcpp/ZrtpSdesStream.h>

#include "../logging/ZrtpLogging.h"
#include "../common/Utilities.h"
#include "gtest/gtest.h"

using namespace std;

static bool verbose = false;
// static bool verbose = true;

// This is the callback that we use for audio stream
class TestCallbackAudio: public CtZrtpCb {
    void onNewZrtpStatus(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) override {
        if (!verbose)
            return;

        fprintf(stderr, "new status: %s\n", p == nullptr ? "NULL" : p);
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

    void onNeedEnroll(CtZrtpSession *session, CtZrtpSession::streamName streamNm, int32_t info) override {
        fprintf(stderr, "Need enroll\n");
    }

    void onPeer(CtZrtpSession *session, char *name, int iIsVerified, CtZrtpSession::streamName streamNm) override {
        fprintf(stderr, "onPeer: %s\n", name == nullptr ? "NULL" : name);
    }

    void onZrtpWarning(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) override {
        fprintf(stderr, "Warning: %s\n", p == nullptr ? "NULL" : p);
    }

    void onDiscriminatorException(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) override {
        fprintf(stderr, "Discriminator: %s\n", p == nullptr ? "NULL" : p);
    }
};

class TestSendCallbackAudio: public CtZrtpSendCb {
    void sendRtp(CtZrtpSession const *session, uint8_t* packet, size_t length, CtZrtpSession::streamName streamNm) override {
        if (!verbose)
            return;
        fprintf(stderr, "ZRTP send packet, length: %zu\n", length);
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


class SdesRunTestFixture: public ::testing::Test {
public:
    SdesRunTestFixture() = default;

    SdesRunTestFixture(const SdesRunTestFixture& other) = delete;
    SdesRunTestFixture(const SdesRunTestFixture&& other) = delete;
    SdesRunTestFixture& operator= (const SdesRunTestFixture& other) = delete;
    SdesRunTestFixture& operator= (const SdesRunTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~SdesRunTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(SdesRunTestFixture, BasicTest) {
    char buffer[200];

    ZrtpSdesStream sdes;

    int rc = sdes.getCryptoMixAttribute(buffer, sizeof(buffer));
    ASSERT_NE(0, rc);

    ASSERT_FALSE(sdes.setCryptoMixAttribute(""));
    ASSERT_TRUE(sdes.setCryptoMixAttribute("HMAC-SHA-384"));
    ASSERT_TRUE(sdes.setCryptoMixAttribute("BABAB HMAC-SHA-384 XYZABC"));
    ASSERT_FALSE(sdes.setCryptoMixAttribute("BABAB XYZABC"));
    // set a valid algorithm that we can check on the next get
//    sdes.setCryptoMixAttribute("BABAB HMAC-SHA-384 XYZABC");

    rc = sdes.getCryptoMixAttribute(buffer, sizeof(buffer));
    size_t len = strlen("HMAC-SHA-384");
    ASSERT_EQ(len, rc);
    ASSERT_EQ(0, strcmp(buffer, "HMAC-SHA-384"));
}

TEST_F(SdesRunTestFixture, NormalSdes) {
    size_t invLength, answLength;
    char invBuffer[200];
    char answBuffer[200];

    auto callback = std::make_unique<TestCallbackAudio>();
    auto sendCallback = std::make_unique<TestSendCallbackAudio>();

    // The Inviter session (offerer)
    std::shared_ptr<ZrtpConfigure> config_i;               // empty ZrtpConfig, CtZrtpSession fills it
    auto inviter = std::make_unique<CtZrtpSession>();
    inviter->init(true, true, 0, "test_i.dat", config_i);        // audio and video
    inviter->setUserCallback(callback.get(), CtZrtpSession::AudioStream);
    inviter->setSendCallback(sendCallback.get(), CtZrtpSession::AudioStream);

    // The answerer session
    std::shared_ptr<ZrtpConfigure> config_a;               // empty ZrtpConfig, CtZrtpSession fills it
    auto answerer = std::make_unique<CtZrtpSession>();
    answerer->init(true, true, 0, "test_a.dat", config_a);         // audio and video
    answerer->setSendCallback(sendCallback.get(), CtZrtpSession::AudioStream);

    // Inviter first step: create a SDES crypto string
    invLength = sizeof(invBuffer);
    inviter->createSdes(invBuffer, &invLength, CtZrtpSession::AudioStream);
    ASSERT_EQ(73, invLength) << "Inviter: SDES crypto string wrong size";   // this is a known value

    // ****
    //  Now send the Inviter SDES crypto string to the answerer via SIP INVITE ........
    // ****

    // answerer first step: parse the SDES crypto string and the answerer SDES creates own crypto string
    answLength = sizeof(answBuffer);
    ASSERT_TRUE(answerer->parseSdes(invBuffer, invLength, nullptr, nullptr, false, CtZrtpSession::AudioStream));

    // answerer second step: get the generated SDES crypto string
    answerer->getSavedSdes(answBuffer, &answLength, CtZrtpSession::AudioStream);
    ASSERT_EQ(73, answLength) << "Answerer: SDES crypto string wrong size";

    // Send the answerer SDES crypto string and crypto mixer algorithms back to Inviter, via 200 OK probably

    // Inviter second step: parses answerer's string, sets the "sipInvite" parameter to true
    ASSERT_TRUE(inviter->parseSdes(answBuffer, answLength, nullptr, nullptr, true, CtZrtpSession::AudioStream));
    inviter->start(0xfeedbac, CtZrtpSession::AudioStream);  // start this stream to get a send callback


    invLength = 0;
    ASSERT_TRUE(inviter->processOutoingRtp(inviterPacket, sizeof(inviterPacket), &invLength, CtZrtpSession::AudioStream));
//    hexdump("Inviter packet protected", inviterPacket, invLength);

    answLength = 0;
    ASSERT_TRUE(answerer->processIncomingRtp(inviterPacket, invLength, &answLength, CtZrtpSession::AudioStream));
    ASSERT_EQ(0, memcmp(inviterPacket, inviterPacket_fixed, answLength))
                                << *zrtp::Utilities::hexdump("Inviter packet unprotected by answerer does not match original data", inviterPacket, answLength);

    answLength = 0;
    answerer->processOutoingRtp(answererPacket, sizeof(answererPacket), &answLength, CtZrtpSession::AudioStream);
//    hexdump("Answerer packet protected", answererPacket, answLength);

    invLength = 0;
    ASSERT_TRUE(inviter->processIncomingRtp(answererPacket, answLength, &invLength, CtZrtpSession::AudioStream));
    ASSERT_EQ(0, memcmp(answererPacket, answererPacket_fixed, invLength))
                                << *zrtp::Utilities::hexdump("Answerer packet unprotected by inviter does not match original data", answererPacket, invLength);
}

TEST_F(SdesRunTestFixture, SdesWithMix) {
    size_t invLength, answLength;
    char invBuffer[200];
    char answBuffer[200];

    char invMixBuffer[200];
    char answMixBuffer[200];

    auto callback = std::make_unique<TestCallbackAudio>();
    auto sendCallback = std::make_unique<TestSendCallbackAudio>();

    // The Inviter session (offerer)
    std::shared_ptr<ZrtpConfigure> config_i;               // empty ZrtpConfig, CtZrtpSession fills it
    auto inviter = std::make_unique<CtZrtpSession>();
    inviter->init(true, true, 0, "test_i.dat", config_i);        // audio and video
    inviter->setUserCallback(callback.get(), CtZrtpSession::AudioStream);
    inviter->setSendCallback(sendCallback.get(), CtZrtpSession::AudioStream);

    // The answerer session
    std::shared_ptr<ZrtpConfigure> config_a;               // empty ZrtpConfig, CtZrtpSession fills it
    auto answerer = std::make_unique<CtZrtpSession>();
    answerer->init(true, true, 0, "test_a.dat", config_a);         // audio and video
    answerer->setSendCallback(sendCallback.get(), CtZrtpSession::AudioStream);

    // Inviter first step: create a SDES crypto string
    invLength = sizeof(invBuffer);
    inviter->createSdes(invBuffer, &invLength, CtZrtpSession::AudioStream);
    ASSERT_EQ(73, invLength) << "Inviter: SDES crypto string wrong size";   // this is a known value

    // Inviter second step: Get all available SDES crypto mix algorithms as nul terminated string
    int invMixLength = sizeof(invMixBuffer);
    invMixLength = inviter->getCryptoMixAttribute(invMixBuffer, invMixLength, CtZrtpSession::AudioStream);
    ASSERT_NE(0, invMixLength) << "Inviter: SDES crypto mixer algorithm returned zero";

    // ****
    //  Now send the Inviter SDES crypto string and the mixer algo string to the answerer via SIP INVITE ........
    // ****

    // answerer first step: set the crypto mix algorithms, the answerer selects one of it
    ASSERT_TRUE(answerer->setCryptoMixAttribute(invMixBuffer, CtZrtpSession::AudioStream));

    // answerer second step: get the seleted crypto mixer algorithm
    int answMixLength = sizeof(answMixBuffer);
    answMixLength = answerer->getCryptoMixAttribute(answMixBuffer, answMixLength, CtZrtpSession::AudioStream);
    ASSERT_NE(0, answMixLength) << "Answerer: SDES crypto mixer algorithm returned zero";

    // answerer third step: parse the SDES crypto string and the answerer SDES creates own crypto string
    answLength = sizeof(answBuffer);
    ASSERT_TRUE(answerer->parseSdes(invBuffer, invLength, nullptr, nullptr, false, CtZrtpSession::AudioStream));

    // answerer fourth step: get the generated SDES crypto string
    answerer->getSavedSdes(answBuffer, &answLength, CtZrtpSession::AudioStream);
    ASSERT_EQ(73, answLength) << "Answerer: SDES crypto string wrong size";

    // additional test: get the seleted crypto mixer algorithm again after parse and check.
    answMixLength = sizeof(answMixBuffer);
    answMixLength = answerer->getCryptoMixAttribute(answMixBuffer, answMixLength, CtZrtpSession::AudioStream);
    ASSERT_NE(0, answMixLength) << "Answerer: SDES crypto mixer algorithm returned zero at second call";

    // Send the answerer SDES crypto string and crypto mixer algorithms back to Inviter, via 200 OK probably

    // Inviter third step: set the received (it's one only) crypto mix algorithm
    ASSERT_TRUE(inviter->setCryptoMixAttribute(answMixBuffer, CtZrtpSession::AudioStream));

    // Inviter fourth step: parses answerer's string, sets the "sipInvite" parameter to true
    ASSERT_TRUE(inviter->parseSdes(answBuffer, answLength, nullptr, nullptr, true, CtZrtpSession::AudioStream));
    inviter->start(0xfeedbac, CtZrtpSession::AudioStream);  // start this stream to get a send callback


    invLength = 0;
    inviter->processOutoingRtp(inviterPacket, sizeof(inviterPacket), &invLength, CtZrtpSession::AudioStream);
//    hexdump("Inviter packet protected", inviterPacket, invLength);

    answLength = 0;
    answerer->processIncomingRtp(inviterPacket, invLength, &answLength, CtZrtpSession::AudioStream);
    ASSERT_EQ(0, memcmp(inviterPacket, inviterPacket_fixed, answLength))
                                << *zrtp::Utilities::hexdump("Inviter packet unprotected by answerer does not match original data", inviterPacket, answLength);

    answLength = 0;
    answerer->processOutoingRtp(answererPacket, sizeof(answererPacket), &answLength, CtZrtpSession::AudioStream);
//    hexdump("Answerer packet protected", answererPacket, answLength);

    invLength = 0;
    inviter->processIncomingRtp(answererPacket, answLength, &invLength, CtZrtpSession::AudioStream);
    ASSERT_EQ(0, memcmp(answererPacket, answererPacket_fixed, invLength))
                                << *zrtp::Utilities::hexdump("Answerer packet unprotected by inviter does not match original data", answererPacket, invLength);
}