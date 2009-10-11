// Test ZRTP extension for ccRTP
//
// Copyright (C) 2008 Werner Dittmann <Werner.Dittmann@t-online.de>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#include <cstdlib>
#include <map>
#include <libzrtpcpp/zrtpccrtp.h>
#include <libzrtpcpp/ZrtpUserCallback.h>

#ifdef  CCXX_NAMESPACES
using namespace ost;
using namespace std;
using namespace GnuZrtpCodes;
#endif

/* maybe should be by special define...
static void hexdump(const char* title, const unsigned char *s, int l) {
    int n=0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x",n);
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}
*/

class PacketsPattern
{
public:
    inline const InetHostAddress&
    getDestinationAddress() const
    { return destinationAddress; }

    inline const tpport_t
    getDestinationPort() const
    { return destinationPort; }

    uint32
    getPacketsNumber() const
    { return packetsNumber; }

    uint32
    getSsrc() const
    { return 0xdeadbeef; }

    const unsigned char*
    getPacketData(uint32 i)
    { return data[i%2]; }

    const size_t
    getPacketSize(uint32 i)
    { return strlen((char*)data[i%2]) + 1 ; }

private:
    static const InetHostAddress destinationAddress;
    static const uint16 destinationPort = 5002;
    static const uint32 packetsNumber = 10;
    static const uint32 packetsSize = 12;
    static const unsigned char* data[];
};

const InetHostAddress PacketsPattern::destinationAddress =
    InetHostAddress("localhost");

const unsigned char* PacketsPattern::data[] = {
    (unsigned char*)"0123456789\n",
    (unsigned char*)"987654321\n"
};

PacketsPattern pattern;

class ZrtpRecvPacketTransmissionTestCB;
class ZrtpSendPacketTransmissionTestCB;
class MyUserCallback;
class MyUserCallbackMulti;

static ZrtpRecvPacketTransmissionTestCB* zrxcb = NULL;
static ZrtpSendPacketTransmissionTestCB* ztxcb = NULL;

static ZrtpRecvPacketTransmissionTestCB* zrxcbMulti = NULL;
static ZrtpSendPacketTransmissionTestCB* ztxcbMulti = NULL;


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

private:
    SymmetricZRTPSession* tx;
    string multiParams;
    string prefix;

public:

    ZrtpSendPacketTransmissionTestCB(): tx(NULL), multiParams("") {};

    void run() {
        doTest();
    }

    int doTest();

    string getMultiStrParams() {
        return tx->getMultiStrParams();
    }

    void setMultiStrParams(string params) {
         multiParams = params;
         return;
    }
};


class
ZrtpRecvPacketTransmissionTestCB: public Thread {

private:
    SymmetricZRTPSession* rx;
    string multiParams;
    string prefix;

public:
    ZrtpRecvPacketTransmissionTestCB(): rx(NULL), multiParams("") {};

    void run() {
        doTest();
    }

    int doTest();

    string getMultiStrParams() {
        return rx->getMultiStrParams();
    }

    void setMultiStrParams(string params) {
        multiParams = params;
        return;
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
class MyUserCallback: public ZrtpUserCallback {

    protected:
        static map<int32, std::string*> infoMap;
        static map<int32, std::string*> warningMap;
        static map<int32, std::string*> severeMap;
        static map<int32, std::string*> zrtpMap;

        static bool initialized;

        SymmetricZRTPSession* session;

        std::string prefix;

    public:
        MyUserCallback(SymmetricZRTPSession* s): session(s), prefix("default: ") {

        if (initialized) {
            return;
        }
        infoMap.insert(pair<int32, std::string*>(InfoHelloReceived, new string("Hello received, preparing a Commit")));
        infoMap.insert(pair<int32, std::string*>(InfoCommitDHGenerated, new string("Commit: Generated a public DH key")));
        infoMap.insert(pair<int32, std::string*>(InfoRespCommitReceived, new string("Responder: Commit received, preparing DHPart1")));
        infoMap.insert(pair<int32, std::string*>(InfoDH1DHGenerated, new string("DH1Part: Generated a public DH key")));
        infoMap.insert(pair<int32, std::string*>(InfoInitDH1Received, new string("Initiator: DHPart1 received, preparing DHPart2")));
        infoMap.insert(pair<int32, std::string*>(InfoRespDH2Received, new string("Responder: DHPart2 received, preparing Confirm1")));
        infoMap.insert(pair<int32, std::string*>(InfoInitConf1Received, new string("Initiator: Confirm1 received, preparing Confirm2")));
        infoMap.insert(pair<int32, std::string*>(InfoRespConf2Received, new string("Responder: Confirm2 received, preparing Conf2Ack")));
        infoMap.insert(pair<int32, std::string*>(InfoRSMatchFound, new string("At least one retained secrets matches - security OK")));
        infoMap.insert(pair<int32, std::string*>(InfoSecureStateOn, new string("Entered secure state")));
        infoMap.insert(pair<int32, std::string*>(InfoSecureStateOff, new string("No more security for this session")));

        warningMap.insert(pair<int32, std::string*>(WarningDHAESmismatch,
                          new string("Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096")));
        warningMap.insert(pair<int32, std::string*>(WarningGoClearReceived, new string("Received a GoClear message")));
        warningMap.insert(pair<int32, std::string*>(WarningDHShort,
                          new string("Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096")));
        warningMap.insert(pair<int32, std::string*>(WarningNoRSMatch, new string("No retained secret matches - verify SAS")));
        warningMap.insert(pair<int32, std::string*>(WarningCRCmismatch, new string("Internal ZRTP packet checksum mismatch - packet dropped")));
        warningMap.insert(pair<int32, std::string*>(WarningSRTPauthError, new string("Dropping packet because SRTP authentication failed!")));
        warningMap.insert(pair<int32, std::string*>(WarningSRTPreplayError, new string("Dropping packet because SRTP replay check failed!")));

        severeMap.insert(pair<int32, std::string*>(SevereHelloHMACFailed, new string("Hash HMAC check of Hello failed!")));
        severeMap.insert(pair<int32, std::string*>(SevereCommitHMACFailed, new string("Hash HMAC check of Commit failed!")));
        severeMap.insert(pair<int32, std::string*>(SevereDH1HMACFailed, new string("Hash HMAC check of DHPart1 failed!")));
        severeMap.insert(pair<int32, std::string*>(SevereDH2HMACFailed, new string("Hash HMAC check of DHPart2 failed!")));
        severeMap.insert(pair<int32, std::string*>(SevereCannotSend, new string("Cannot send data - connection or peer down?")));
        severeMap.insert(pair<int32, std::string*>(SevereProtocolError, new string("Internal protocol error occured!")));
        severeMap.insert(pair<int32, std::string*>(SevereNoTimer, new string("Cannot start a timer - internal resources exhausted?")));
        severeMap.insert(pair<int32, std::string*>(SevereTooMuchRetries,
                         new string("Too much retries during ZRTP negotiation - connection or peer down?")));

        zrtpMap.insert(pair<int32, std::string*>(MalformedPacket, new string("Malformed packet (CRC OK, but wrong structure)")));
        zrtpMap.insert(pair<int32, std::string*>(CriticalSWError, new string("Critical software error")));
        zrtpMap.insert(pair<int32, std::string*>(UnsuppZRTPVersion, new string("Unsupported ZRTP version")));
        zrtpMap.insert(pair<int32, std::string*>(HelloCompMismatch, new string("Hello components mismatch")));
        zrtpMap.insert(pair<int32, std::string*>(UnsuppHashType, new string("Hash type not supported")));
        zrtpMap.insert(pair<int32, std::string*>(UnsuppCiphertype, new string("Cipher type not supported")));
        zrtpMap.insert(pair<int32, std::string*>(UnsuppPKExchange, new string("Public key exchange not supported")));
        zrtpMap.insert(pair<int32, std::string*>(UnsuppSRTPAuthTag, new string("SRTP auth. tag not supported")));
        zrtpMap.insert(pair<int32, std::string*>(UnsuppSASScheme, new string("SAS scheme not supported")));
        zrtpMap.insert(pair<int32, std::string*>(NoSharedSecret, new string("No shared secret available, DH mode required")));
        zrtpMap.insert(pair<int32, std::string*>(DHErrorWrongPV, new string("DH Error: bad pvi or pvr ( == 1, 0, or p-1)")));
        zrtpMap.insert(pair<int32, std::string*>(DHErrorWrongHVI, new string("DH Error: hvi != hashed data")));
        zrtpMap.insert(pair<int32, std::string*>(SASuntrustedMiTM, new string("Received relayed SAS from untrusted MiTM")));
        zrtpMap.insert(pair<int32, std::string*>(ConfirmHMACWrong, new string("Auth. Error: Bad Confirm pkt HMAC")));
        zrtpMap.insert(pair<int32, std::string*>(NonceReused, new string("Nonce reuse")));
        zrtpMap.insert(pair<int32, std::string*>(EqualZIDHello, new string("Equal ZIDs in Hello")));
        zrtpMap.insert(pair<int32, std::string*>(GoCleatNotAllowed, new string("GoClear packet received, but not allowed")));

        initialized = true;
        }

        void showMessage(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) {
            string* msg;
            if (sev == Info) {
                msg = infoMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
                // this sets up and starts off the multi-stream test
                if (subCode == InfoSecureStateOn) {
                    if (zrxcbMulti != NULL) {
                        zrxcbMulti->setMultiStrParams(session->getMultiStrParams());
                        zrxcbMulti->start();
                    }
                    if (ztxcbMulti != NULL) {
                        ztxcbMulti->setMultiStrParams(session->getMultiStrParams());
                        ztxcbMulti->start();
                    }
                }
            }
            if (sev == Warning) {
                msg = warningMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
            if (sev == Severe) {
                msg = severeMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
            if (sev == ZrtpError) {
                if (subCode < 0) {  // received an error packet from peer
                    subCode *= -1;
                    cout << prefix << "Received error packet: ";
                }
                else {
                    cout << prefix << "Sent error packet: ";
                }
                msg = zrtpMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
        }

        void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) {
            string* msg;
            if (sev == ZrtpError) {
                if (subCode < 0) {  // received an error packet from peer
                    subCode *= -1;
                    cout << prefix << "Received error packet: ";
                }
                else {
                    cout << prefix << "Sent error packet: ";
                }
                msg = zrtpMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
            else {
                msg = severeMap[subCode];
                cout << prefix << *msg << endl;
            }
        }

        void secureOn(std::string cipher) {
            cout << prefix << "Using cipher:" << cipher << endl;
        }

        void showSAS(std::string sas, bool verified) {
            cout << prefix << "SAS is: " << sas << endl;

        }

        void setPrefix(std::string p) {
            prefix = p;
        }
};

map<int32, std::string*>MyUserCallback::infoMap;
map<int32, std::string*>MyUserCallback::warningMap;
map<int32, std::string*>MyUserCallback::severeMap;
map<int32, std::string*>MyUserCallback::zrtpMap;

bool MyUserCallback::initialized = false;


class MyUserCallbackMulti: public MyUserCallback {

    public:

        MyUserCallbackMulti(SymmetricZRTPSession* s): MyUserCallback(s) {
        }

        void showMessage(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) {
            string* msg;
            if (sev == Info) {
                msg = infoMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
            if (sev == Warning) {
                msg = warningMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
            if (sev == Severe) {
                msg = severeMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
            if (sev == ZrtpError) {
                if (subCode < 0) {  // received an error packet from peer
                    subCode *= -1;
                    cout << prefix << "Received error packet: ";
                }
                else {
                    cout << prefix << "Sent error packet: ";
                }
                msg = zrtpMap[subCode];
                if (msg != NULL) {
                    cout << prefix << *msg << endl;
                }
            }
        }
};

int ZrtpSendPacketTransmissionTestCB::doTest() {

        MyUserCallback* mcb;
        if (!multiParams.empty()) {
            tx = new SymmetricZRTPSession(pattern.getDestinationAddress(),
                                    pattern.getDestinationPort()+2+10);
            tx->initialize("test_t.zid");
            tx->setMultiStrParams(multiParams);

            prefix = "TX Multi: ";
            mcb = new MyUserCallback(tx);
            mcb->setPrefix(prefix);
        }
        else {
            tx = new SymmetricZRTPSession(pattern.getDestinationAddress(),
                                    pattern.getDestinationPort()+2);
            tx->initialize("test_t.zid");

            prefix = "TX: ";
            mcb = new MyUserCallback(tx);
            mcb->setPrefix(prefix);
        }
        // At this point the Hello hash is available. See ZRTP specification
        // chapter 9.1 for further information when an how to use the Hello
        // hash.
        cout << prefix << "Hello hash: " << tx->getHelloHash() << endl;
        cout << prefix << "Hello hash length: " << tx->getHelloHash().length() << endl;
        tx->setUserCallback(mcb);
        tx->setSchedulingTimeout(10000);
        tx->setExpireTimeout(1000000);

        tx->startRunning();

        tx->setPayloadFormat(StaticPayloadFormat(sptPCMU));

        if (!multiParams.empty()) {
            if (!tx->addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()+10) ) {
            return 1;
            }
        }
        else {
            if (!tx->addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()) ) {
            return 1;
            }
        }
        tx->startZrtp();

        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx->getCurrentRTPClockRate()/2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++ ) {
            tx->putData(i*inc,
                       pattern.getPacketData(i),
                       pattern.getPacketSize(i));
            cout << prefix << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx->putData(i*inc, (unsigned char*)"exit", 5);
        Thread::sleep(TimerPort::getTimer());
        delete tx;
        return 0;
    }


int ZrtpRecvPacketTransmissionTestCB::doTest() {

        MyUserCallback* mcb;
        if (!multiParams.empty()) {
            rx = new SymmetricZRTPSession(pattern.getDestinationAddress(),
                                pattern.getDestinationPort()+10);

            rx->initialize("test_r.zid");
            rx->setMultiStrParams(multiParams);

            prefix = "RX Multi: ";
            mcb = new MyUserCallbackMulti(rx);
            mcb->setPrefix(prefix);
        }
        else {
            rx = new SymmetricZRTPSession(pattern.getDestinationAddress(),
                                    pattern.getDestinationPort());

            rx->initialize("test_r.zid");

            prefix = "RX: ";
            mcb = new MyUserCallback(rx);
            mcb->setPrefix(prefix);
        }
        // At this point the Hello hash is available. See ZRTP specification
        // chapter 9.1 for further information when an how to use the Hello
        // hash.
        cout << prefix << "Hello hash: " << rx->getHelloHash() << endl;
        cout << prefix << "Hello hash length: " << rx->getHelloHash().length() << endl;
        rx->setUserCallback(mcb);
        rx->setSchedulingTimeout(10000);
        rx->setExpireTimeout(1000000);

        rx->startRunning();
        rx->setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        if (!multiParams.empty()) {
            if (!rx->addDestination(pattern.getDestinationAddress(),
                                pattern.getDestinationPort()+2+10) ) {
                return 1;
            }
        }
        else {
            if (!rx->addDestination(pattern.getDestinationAddress(),
                                pattern.getDestinationPort()+2) ) {
                return 1;
            }
        }
//        rx->startZrtp();

        for ( int i = 0; i < 5000 ; i++ ) {
            const AppDataUnit* adu;
            while ( (adu = rx->getData(rx->getFirstTimestamp())) ) {
                cerr << prefix << "got some data: " << adu->getData() << endl;
                if (*adu->getData() == 'e') {
                    delete adu;
                    delete rx;
                    return 0;
                }
                delete adu;
            }
            Thread::sleep(70);
        }
        delete rx;
        return 0;
    }


int main(int argc, char *argv[])
{
    int result = 0;
    bool send = false;
    bool recv = false;

    char c;

    /* check args */
    while (1) {
        c = getopt(argc, argv, "rs");
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
        default:
            cerr << "Wrong Arguments, only -s and -r are accepted" << endl;
        }
    }

    if (send || recv) {
        if (send) {
            cout << "Running as sender" << endl;
        }
        else {
            cout << "Running as receiver" << endl;
        }
    }
    else {
        cerr << "No send or receive argument specificied" << endl;
        exit(1);
    }

    if ( send ) {
        ztxcb = new ZrtpSendPacketTransmissionTestCB();
        ztxcbMulti = new ZrtpSendPacketTransmissionTestCB();
        ztxcb->start();
        ztxcb->join();
        ztxcbMulti->join();
    } else if ( recv ) {
        zrxcb = new ZrtpRecvPacketTransmissionTestCB();
        zrxcbMulti = new ZrtpRecvPacketTransmissionTestCB();
        zrxcb->start();
        zrxcb->join();
        zrxcbMulti->join();
    }

    exit(result);
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
