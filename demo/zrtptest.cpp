/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Test ZRTP extension for ccRTP

#include <cstdlib>
#include <map>
#include <memory>

#include <zrtpccrtp.h>
#include <helpers/ZrtpUserCallbackEmpty.h>
#include <helpers/ZrtpCodeToString.h>
#include <logging/ZrtpLogging.h>
#include <cryptcommon/sidhp751/keymanagement/SidhKeyManagement.h>
#include <common/osSpecifics.h>
#include <zrtp/libzrtpcpp/ZIDCacheFile.h>

using namespace ost;
using namespace std;
using namespace GnuZrtpCodes;

class PacketsPattern {
public:
    inline const InetHostAddress &getReceiverAddress() const { return *receiverAddress; }

    inline const InetHostAddress &getSenderAddress() const { return *senderAddress; }

    inline void setReceiverAddress(InetHostAddress *addr) const {
        delete receiverAddress;
        receiverAddress = addr;
    }

    inline void setSenderAddress(InetHostAddress *addr) const {
        delete senderAddress;
        senderAddress = addr;
    }

    inline tpport_t getReceiverPort() const { return receiverPort; }

    inline tpport_t getSenderPort() const { return senderPort; }

    uint32 getPacketsNumber() const { return packetsNumber; }

    uint32 getSsrc() const { return 0xdeadbeef; }

    static const unsigned char *getPacketData(uint32 i) { return data[i % 2]; }

    static size_t getPacketSize(uint32 i) { return strlen((char *) data[i % 2]) + 1; }

private:
    static const InetHostAddress *receiverAddress;
    static const InetHostAddress *senderAddress;

    static const uint16 receiverPort = 5002;
    static const uint16 senderPort = 5004;
    static const uint32 packetsNumber = 10;
    static const unsigned char *data[];
};

const InetHostAddress *PacketsPattern::receiverAddress = new InetHostAddress("localhost");
const InetHostAddress *PacketsPattern::senderAddress = new InetHostAddress("localhost");

const unsigned char *PacketsPattern::data[] = {
        (unsigned char *) "0123456789\n",
        (unsigned char *) "987654321\n"
};

PacketsPattern pattern;

static ZrtpCodeToString codeToString;

class ExtZrtpSession : public SymmetricZRTPSession { // , public std::enable_shared_from_this<ExtZrtpSession> {
//     ExtZrtpSession(InetMcastAddress& ima, tpport_t port) :
//     RTPSession(ima,port) {}
// 
//     ExtZrtpSession(InetHostAddress& ia, tpport_t port) :
//     RTPSession(ia,port) {}

public:

    // factory function that perfect-forwards args to a private ctor
    template<typename ... T>
    static std::shared_ptr<ExtZrtpSession> create(T&& ... t) {
        return std::shared_ptr<ExtZrtpSession>(new ExtZrtpSession(std::forward<T>(t)...));
    }

    void onGotGoodbye(const SyncSource &source, const std::string &reason) override {
        cout << "I got a Goodbye packet from "
             << hex << (int) source.getID() << "@"
             << dec
             << source.getNetworkAddress() << ":"
             << source.getControlTransportPort() << endl;
        cout << "   Goodbye reason: \"" << reason << "\"" << '\n';
    }

    // redefined from QueueRTCPManager
    void onGotRR(SyncSource &source, RecvReport &RR, uint8 blocks) override {
        SingleThreadRTPSession::onGotRR(source, RR, blocks);
        cout << "I got an RR RTCP report from "
             << hex << (int) source.getID() << "@"
             << dec
             << source.getNetworkAddress() << ":"
             << source.getControlTransportPort() << '\n';
    }

private:
    ExtZrtpSession(uint32 ssrc, const InetHostAddress &ia, tpport_t dataPort) :
            SingleThreadRTPSession(ssrc, ia, dataPort) {
        cout << "Extended" << endl;
    }

    ExtZrtpSession(const InetHostAddress &ia, tpport_t dataPort) : SingleThreadRTPSession(ia, dataPort) {
        cout << "Extended" << endl;
    }
};


/*
 * The following classes use:
 * - localAddress and destination port+2 for the sender classes
 * - destinationAddress and destination port for the receiver classes.
 * 
 */

/**
 * SymmetricZRTPSession in non-security mode (RTPSession compatible).
 *
 * The next two classes show how to use <code>SymmetricZRTPSession</code>
 * in the same way as <code>RTPSession</code>. This is straightforward,
 * just don't do any configuration or initialization.
 */
class SendPacketTransmissionTest : public Thread, public TimerPort {
public:
    void
    run() override {
        doTest();
    }

    int doTest() {
        // should be valid?
        //RTPSession tx();
        auto tx = ExtZrtpSession::create(pattern.getSsrc(), pattern.getSenderAddress(), pattern.getSenderPort());
//        SymmetricZRTPSession tx(pattern.getSsrc(), InetHostAddress("localhost"));
        tx->setSchedulingTimeout(10000);
        tx->setExpireTimeout(1000000);

        tx->startRunning();

        tx->setPayloadFormat(StaticPayloadFormat(sptPCMU));

        // We are sender:
        if (!tx->addDestination(pattern.getReceiverAddress(), pattern.getReceiverPort())) {
            return 1;
        }

        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx->getCurrentRTPClockRate() / 2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++) {
            tx->putData(i * inc, PacketsPattern::getPacketData(i), PacketsPattern::getPacketSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx->putData(i * inc, (unsigned char *) "exit", 5);
        Thread::sleep(TimerPort::getTimer());
        return 0;
    }
};


class RecvPacketTransmissionTest : public Thread {
public:
    void
    run() override {
        doTest();
    }

    static int
    doTest() {
        auto rx = ExtZrtpSession::create(pattern.getSsrc() + 1, pattern.getReceiverAddress(), pattern.getReceiverPort());

//         SymmetricZRTPSession rx(pattern.getSsrc()+1, pattern.getDestinationAddress(),
//                                 pattern.getDestinationPort());
        rx->setSchedulingTimeout(10000);
        rx->setExpireTimeout(1000000);

        rx->startRunning();
        rx->setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        if (!rx->addDestination(pattern.getSenderAddress(), pattern.getSenderPort())) {
            return 1;
        }
        for (int i = 0; i < 5000; i++) {
            const AppDataUnit *adu;
            while ((adu = rx->getData(rx->getFirstTimestamp()))) {
                cerr << "got some data: " << adu->getData() << endl;
                if (*adu->getData() == 'e') {
                    delete adu;
                    return 0;
                }
                delete adu;
            }
            Thread::sleep(70);
        }
        return 0;
    }
};


/**
 * SymmetricZRTPSession in security mode.
 *
 * The next two classes show how to use <code>SymmetricZRTPSession</code>
 * using the standard ZRTP handshake an switching to encrypted (SRTP) mode.
 * The application enables this by calling <code>initialize(...)</code>.
 * Some embedded logging informs about the ZRTP processing.
 */

class ZrtpSendPacketTransmissionTest : public Thread, public TimerPort {
public:
    void
    run() override {
        doTest();
    }

    int doTest() {
        // should be valid?
        //RTPSession tx();
        // Initialize with local address and Local port is detination port +2 - keep RTP/RTCP port pairs
        auto tx = ExtZrtpSession::create(pattern.getSsrc(), pattern.getSenderAddress(), pattern.getSenderPort());

        std::shared_ptr<ZrtpConfigure> config;      // empty shared pointer, no own configuration
        tx->initialize("test_t.zid", true, config);
        tx->setSchedulingTimeout(10000);
        tx->setExpireTimeout(1000000);
        tx->startRunning();
        tx->setPayloadFormat(StaticPayloadFormat(sptPCMU));
        if (!tx->addDestination(pattern.getReceiverAddress(), pattern.getReceiverPort())) {
            return 1;
        }
        tx->startZrtp();
        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx->getCurrentRTPClockRate() / 2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++) {
            tx->putData(i * inc,
                       PacketsPattern::getPacketData(i),
                       PacketsPattern::getPacketSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx->putData(i * inc, (unsigned char *) "exit", 5);
        Thread::sleep(200);
        return 0;
    }
};

class ZrtpRecvPacketTransmissionTest : public Thread {
public:
    void
    run() override {
        doTest();
    }

    static int
    doTest() {
        auto rx = ExtZrtpSession::create(pattern.getSsrc() + 1, pattern.getReceiverAddress(), pattern.getReceiverPort());

        std::shared_ptr<ZrtpConfigure> config;      // empty shared pointer, no own configuration
        rx->initialize("test_r.zid", true, config);
        rx->setSchedulingTimeout(10000);
        rx->setExpireTimeout(1000000);
        rx->startRunning();
        rx->setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        if (!rx->addDestination(pattern.getSenderAddress(), pattern.getSenderPort())) {
            return 1;
        }
        rx->startZrtp();
        for (int i = 0; i < 5000; i++) {
            const AppDataUnit *adu;
            while ((adu = rx->getData(rx->getFirstTimestamp()))) {
                cerr << "got some data: " << adu->getData() << endl;
                if (*adu->getData() == 'e') {
                    delete adu;
                    return 0;
                }
                delete adu;
            }
            Thread::sleep(70);
        }
        return 0;
    }
};

/**
 * Simple User Callback class
 *
 * This class overwrite some methods from ZrtpUserCallback to get information
 * about ZRTP processing and information about ZRTP results. The standard
 * implementation of this class just perform return, thus effectively
 * supressing any callback or trigger.
 */
class MyUserCallback : public ZrtpUserCallbackEmpty {

public:
    explicit MyUserCallback()  = default;

    void showMessage(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) override {
        cout << codeToString.getStringForCode(sev, subCode) << '\n';
    }

    void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) override {
        cout << codeToString.getStringForCode(sev, subCode) << '\n';
    }

    void secureOn(std::string cipher) override {
        cout << "Using cipher:" << cipher << endl;
    }

    void showSAS(std::string sas, bool verified) override {
        cout << "SAS is: " << sas << endl;
    }
};

static unsigned char transmAuxSecret[] = {1,2,3,4,5,6,7,8,9,0};

static std::shared_ptr<ZIDCache> zrtpCache = nullptr;

static std::shared_ptr<ZIDCache>
initCache(const char *zidFilename, std::shared_ptr<ZIDCache> cache) {
    std::string fname;
    if (!zidFilename) {
        char *home = getenv("HOME");
        std::string baseDir = (home) ? (std::string(home) + std::string("/."))
                                     : std::string(".");
        fname = baseDir + std::string("GNUZRTP.zid");
        zidFilename = fname.c_str();
    }

    // Check if a cache is available.
    // If yes and it has the same filename -> use it
    // otherwise close file and open new cache file
    if (cache) {
        if (cache->getFileName() == zidFilename) {
            return cache;
        }
        cache->close();
        if (cache->open((char *) zidFilename) < 0) {
            return std::shared_ptr<ZIDCache>();
        }
        return cache;
    }

    auto zf = std::make_shared<ZIDCacheFile>();
    if (zf->open((char *) zidFilename) < 0) {
        return std::shared_ptr<ZIDCache>();
    }
    return zf;
}

/**
 * SymmetricZRTPSession in security mode and using a callback class.
 *
 * The next two classes show how to use <code>SymmetricZRTPSession</code>
 * using the standard ZRTP handshake an switching to encrypted (SRTP) mode.
 * The application enables this by calling <code>initialize(...)</code>.
 * In addition the application sets a callback class (see above). ZRTP calls
 * the methods of the callback class and the application may implement
 * appropriate methods to deal with these triggers.
 */

class
ZrtpSendPacketTransmissionTestCB : public Thread, public TimerPort {
public:

    shared_ptr<ZrtpConfigure> config = std::make_shared<ZrtpConfigure>();

    void run() override {
        doTest();
    }

    int doTest() {
        // should be valid?
        //RTPSession tx();
        auto tx = ExtZrtpSession::create(/*pattern.getSsrc(),*/ pattern.getSenderAddress(), pattern.getSenderPort());
        config->clear();

        auto zf = initCache("test_t.zid", zrtpCache);
        if (!zf) {
            return -1;
        }
        if (!zrtpCache) {
            zrtpCache = zf;
        }
        config->setZidCache(zf);

        // config.setStandardConfig();
        // config.addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("DH2k"));
        // config.addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("DH3k"));

        // This ordering prefers NIST
//        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH1"));
        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC38"));
        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E414"));

        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC25"));
        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E255"));

        config->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
        config->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));

        config->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));
        config->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));

        config->addAlgo(SasType, zrtpSasTypes.getByName("B256"));

        config->addAlgo(AuthLength, zrtpAuthLengths.getByName("HS32"));
        config->addAlgo(AuthLength, zrtpAuthLengths.getByName("HS80"));
        config->addAlgo(AuthLength, zrtpAuthLengths.getByName("SK32"));
        config->addAlgo(AuthLength, zrtpAuthLengths.getByName("SK64"));

        tx->initialize("test_t.zid", true, config);
        // At this point the Hello hash is available. See ZRTP specification
        // chapter 9.1 for further information when an how to use the Hello
        // hash.
        int numSupportedVersion = tx->getNumberSupportedVersions();
        cout << "TX Hello hash 0: " << tx->getHelloHash(0) << endl;
        cout << "TX Hello hash 0 length: " << tx->getHelloHash(0).length() << endl;
        if (numSupportedVersion > 1) {
            cout << "TX Hello hash 1: " << tx->getHelloHash(1) << endl;
            cout << "TX Hello hash 1 length: " << tx->getHelloHash(1).length() << endl;
        }
        tx->setUserCallback(new MyUserCallback());
        tx->setAuxSecret(transmAuxSecret, sizeof(transmAuxSecret));
        tx->setSchedulingTimeout(10000);
        tx->setExpireTimeout(1000000);
        tx->startRunning();
        tx->setPayloadFormat(StaticPayloadFormat(sptPCMU));

        if (!tx->addDestination(pattern.getReceiverAddress(), pattern.getReceiverPort())) {
            return 1;
        }
        tx->startZrtp();

        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx->getCurrentRTPClockRate() / 2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++) {
            tx->putData(i * inc, PacketsPattern::getPacketData(i), PacketsPattern::getPacketSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx->putData(i * inc, (unsigned char *) "exit", 5);
        Thread::sleep(TimerPort::getTimer());
        return 0;
    }
};

static unsigned char recvAuxSecret[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 9};

class
ZrtpRecvPacketTransmissionTestCB : public Thread {
public:
    shared_ptr<ZrtpConfigure> config = std::make_shared<ZrtpConfigure>();

    void run() override {
        doTest();
    }

    int doTest() {
        auto rx = ExtZrtpSession::create( /*pattern.getSsrc()+1,*/ pattern.getReceiverAddress(), pattern.getReceiverPort());
        config->clear();

        auto zf = initCache("test_r.zid", zrtpCache);
        if (!zf) {
            return -1;
        }
        if (!zrtpCache) {
            zrtpCache = zf;
        }
        config->setZidCache(zf);

        //        config.setStandardConfig();
//         config.addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("DH3k"));

        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E414"));
        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC38"));
        config->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH1"));

        config->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
        config->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));

//          config.addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));
//          config.addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));

        config->addAlgo(SasType, zrtpSasTypes.getByName("B256"));


        rx->initialize("test_r.zid", true, config);
        // At this point the Hello hash is available. See ZRTP specification
        // chapter 9.1 for further information when an how to use the Hello
        // hash.
        int numSupportedVersion = rx->getNumberSupportedVersions();
        cout << "RX Hello hash 0: " << rx->getHelloHash(0) << endl;
        cout << "RX Hello hash 0 length: " << rx->getHelloHash(0).length() << endl;
        if (numSupportedVersion > 1) {
            cout << "RX Hello hash 1: " << rx->getHelloHash(1) << endl;
            cout << "RX Hello hash 1 length: " << rx->getHelloHash(1).length() << endl;
        }
        rx->setUserCallback(new MyUserCallback());
        rx->setAuxSecret(recvAuxSecret, sizeof(recvAuxSecret));
        rx->setSchedulingTimeout(10000);
        rx->setExpireTimeout(1000000);
        rx->startRunning();
        rx->setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        if (!rx->addDestination(pattern.getSenderAddress(), pattern.getSenderPort())) {
            return 1;
        }
        rx->startZrtp();

        for (int i = 0; i < 5000; i++) {
            const AppDataUnit *adu;
            while ((adu = rx->getData(rx->getFirstTimestamp()))) {
                cerr << "got some data: " << adu->getData() << endl;
                if (*adu->getData() == 'e') {
                    delete adu;
                    return 0;
                }
                delete adu;
            }
            Thread::sleep(500);
        }
        return 0;
    }
};


int main(int argc, char *argv[]) {
    int result = 0;
    bool send = false;
    bool recv = false;

    char c;

    /* check args */
    while (true) {
        c = getopt(argc, argv, "rsR:S:");
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'r':
                recv = true;
                break;
            case 's':
                send = true;
                break;
            case 'R':
                pattern.setReceiverAddress(new InetHostAddress(optarg));
                break;
            case 'S':
                pattern.setSenderAddress(new InetHostAddress(optarg));
                break;
            default:
                cerr << "Wrong Arguments, only -s and -r are accepted" << endl;
        }
    }

    if (send || recv) {
        if (send) {
            cout << "Running as sender" << endl;
        } else {
            cout << "Running as receiver" << endl;
        }
    } else {
        cerr << "No send or receive argument specified" << endl;
        exit(1);
    }

    // accept as parameter if must run as --send or --recv

#if 0
    RecvPacketTransmissionTest *rx;
    SendPacketTransmissionTest *tx;

   // run several tests in parallel threads
   if ( send ) {
       tx = new SendPacketTransmissionTest();
       tx->start();
       tx->join();
   } else if ( recv ) {
       rx = new RecvPacketTransmissionTest();
       rx->start();
       rx->join();
   }
//#endif
//#if 0
   ZrtpRecvPacketTransmissionTest *zrx;
   ZrtpSendPacketTransmissionTest *ztx;

   if ( send ) {
       ztx = new ZrtpSendPacketTransmissionTest();
       ztx->start();
       ztx->join();
   } else if ( recv ) {
       zrx = new ZrtpRecvPacketTransmissionTest();
       zrx->start();
       zrx->join();
   }
#endif
    ZrtpRecvPacketTransmissionTestCB *zrxcb;
    ZrtpSendPacketTransmissionTestCB *ztxcb;

    if (send) {
//    setZrtpLogLevel(DEBUGGING);
        if (send) {
            ztxcb = new ZrtpSendPacketTransmissionTestCB();
            ztxcb->start();
            ztxcb->join();
            delete ztxcb;
        } else {
            zrxcb = new ZrtpRecvPacketTransmissionTestCB();
            zrxcb->start();
            zrxcb->join();
            delete zrxcb;
        }
        Thread::sleep(1000);
        exit(result);
    }
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
