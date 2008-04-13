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
#include <libzrtpcpp/zrtpccrtp.h>
#include <libzrtpcpp/ZrtpUserCallback.h>

#ifdef  CCXX_NAMESPACES
using namespace ost;
using namespace std;
#endif

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
    static const uint16 destinationPort = 10002;
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

class
Test
{
public:
    virtual int
    doTest() = 0;
};

/**
 * SymmetricZRTPSession in non-security mode (RTPSession compatible).
 *
 * The next two classes show how to use <code>SymmetricZRTPSession</code>
 * in the same way as <code>RTPSession</code>. This is straightforward,
 * just don't do any configuration or initialization.
 */
class
SendPacketTransmissionTest : public Test, public Thread, public TimerPort
{
public:
    void
    run()
    {
        doTest();
    }

    int doTest()
    {
        // should be valid?
        //RTPSession tx();
        SymmetricZRTPSession tx(pattern.getSsrc(), InetHostAddress("localhost"));
        tx.setSchedulingTimeout(10000);
        tx.setExpireTimeout(1000000);

        tx.startRunning();

        tx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        if (!tx.addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()) ) {
            return 1;
        }

        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx.getCurrentRTPClockRate()/2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++ ) {
            tx.putData(i*inc,
                       pattern.getPacketData(i),
                       pattern.getPacketSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx.putData(i*inc, (unsigned char*)"exit", 5);
        cout << "Sent exit string: " << i << endl;
        Thread::sleep(TimerPort::getTimer());
        return 0;
    }
};


class
RecvPacketTransmissionTest : public Test, public Thread
{
public:
    void
    run() {
        doTest();
    }

    int
    doTest() {
        SymmetricZRTPSession rx(pattern.getSsrc(), pattern.getDestinationAddress(),
                                pattern.getDestinationPort());

        rx.setSchedulingTimeout(10000);
        rx.setExpireTimeout(1000000);

        rx.startRunning();
        rx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        for ( int i = 0; i < 5000 ; i++ ) {
            const AppDataUnit* adu;
            while ( (adu = rx.getData(rx.getFirstTimestamp())) ) {
                cerr << "got some data: " << adu->getData() << endl;
                if (*adu->getData() == 'e') {
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

class
ZrtpSendPacketTransmissionTest : public Test, public Thread, public TimerPort
{
public:
    void
    run()
    {
        doTest();
    }

    int doTest()
    {
        // should be valid?
        //RTPSession tx();
        SymmetricZRTPSession tx(pattern.getSsrc(), pattern.getDestinationAddress(),
                                pattern.getDestinationPort()+2);
        tx.initialize("test_t.zid");

        tx.setSchedulingTimeout(10000);
        tx.setExpireTimeout(1000000);

        tx.startRunning();

        tx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        if (!tx.addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()) ) {
            return 1;
        }
        tx.startZrtp();
        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx.getCurrentRTPClockRate()/2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++ ) {
            tx.putData(i*inc,
                       pattern.getPacketData(i),
                       pattern.getPacketSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx.putData(i*inc, (unsigned char*)"exit", 5);
        cout << "Sent exit string: " << i << endl;
        Thread::sleep(TimerPort::getTimer());
        return 0;
    }
};

class
ZrtpRecvPacketTransmissionTest : public Test, public Thread
{
public:
    void
    run() {
        doTest();
    }

    int
    doTest() {
        SymmetricZRTPSession rx(pattern.getSsrc(), pattern.getDestinationAddress(),
                                pattern.getDestinationPort());

        rx.initialize("test_r.zid");

        rx.setSchedulingTimeout(10000);
        rx.setExpireTimeout(1000000);

        rx.startRunning();
        rx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        if (!rx.addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()+2) ) {
            return 1;
        }
        rx.startZrtp();
        for ( int i = 0; i < 5000 ; i++ ) {
            const AppDataUnit* adu;
            while ( (adu = rx.getData(rx.getFirstTimestamp())) ) {
                cerr << "got some data: " << adu->getData() << endl;
                if (*adu->getData() == 'e') {
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
class
MyUserCallback: public ZrtpUserCallback {
    void secureOn(std::string cipher) {
        cout << "Using cipher:" << cipher << endl;
    }

    void showSAS(std::string sas, bool verified) {
        cout << "SAS is: " << sas << endl;

    }
};

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
ZrtpSendPacketTransmissionTestCB : public Test, public Thread, public TimerPort
{
public:
    void
    run()
    {
        doTest();
    }

    int doTest()
    {
        // should be valid?
        //RTPSession tx();
        SymmetricZRTPSession tx(pattern.getSsrc(), pattern.getDestinationAddress(),
                                pattern.getDestinationPort()+2);
        tx.initialize("test_t.zid");
        tx.setUserCallback(new MyUserCallback());

        tx.setSchedulingTimeout(10000);
        tx.setExpireTimeout(1000000);

        tx.startRunning();

        tx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        if (!tx.addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()) ) {
            return 1;
        }
        tx.startZrtp();
        // 2 packets per second (packet duration of 500ms)
        uint32 period = 500;
        uint16 inc = tx.getCurrentRTPClockRate()/2;
        TimerPort::setTimer(period);
        uint32 i;
        for (i = 0; i < pattern.getPacketsNumber(); i++ ) {
            tx.putData(i*inc,
                       pattern.getPacketData(i),
                       pattern.getPacketSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx.putData(i*inc, (unsigned char*)"exit", 5);
        cout << "Sent exit string: " << i << endl;
        Thread::sleep(TimerPort::getTimer());
        return 0;
    }
};


class
ZrtpRecvPacketTransmissionTestCB : public Test, public Thread
{
public:
    void
    run() {
        doTest();
    }

    int
    doTest() {
        SymmetricZRTPSession rx(pattern.getSsrc(), pattern.getDestinationAddress(),
                                pattern.getDestinationPort());

        rx.initialize("test_r.zid");
        rx.setUserCallback(new MyUserCallback());

        rx.setSchedulingTimeout(10000);
        rx.setExpireTimeout(1000000);

        rx.startRunning();
        rx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        // arbitrary number of loops to provide time to start transmitter
        if (!rx.addDestination(pattern.getDestinationAddress(),
                               pattern.getDestinationPort()+2) ) {
            return 1;
        }
        rx.startZrtp();
        for ( int i = 0; i < 5000 ; i++ ) {
            const AppDataUnit* adu;
            while ( (adu = rx.getData(rx.getFirstTimestamp())) ) {
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
            cerr << "Wrong Arguments" << endl;
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
    RecvPacketTransmissionTest *rx;
    SendPacketTransmissionTest *tx;

    // accept as parameter if must run as --send or --recv

#if 0
    // run several tests in parallel threads
    if ( send ) {
        tx = new SendPacketTransmissionTest();
        tx->start();
        tx->join();
    } else      if ( recv ) {
        rx = new RecvPacketTransmissionTest();
        rx->start();
        rx->join();
    }
#endif
#if 0
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

    if ( send ) {
        ztxcb = new ZrtpSendPacketTransmissionTestCB();
        ztxcb->start();
        ztxcb->join();
    } else if ( recv ) {
        zrxcb = new ZrtpRecvPacketTransmissionTestCB();
        zrxcb->start();
        zrxcb->join();
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
