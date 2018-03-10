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
/*
    This class maps the ZRTP C calls to ZRTP C++ methods.
*/

#include <libzrtpcpp/ZrtpCWrapper.h>

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* Forward declaration of the ZRTP specific callback functions that this
  adapter must implement */
static int32_t zrtp_sendDataZRTP (ZrtpContext* ctx, const uint8_t* data, int32_t length ) ;
static int32_t zrtp_activateTimer (ZrtpContext* ctx, int32_t time ) ;
static int32_t zrtp_cancelTimer(ZrtpContext* ctx) ;
static void zrtp_sendInfo (ZrtpContext* ctx, int32_t severity, int32_t subCode ) ;
static int32_t zrtp_srtpSecretsReady (ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part ) ;
static void zrtp_srtpSecretsOff (ZrtpContext* ctx, int32_t part ) ;
static void zrtp_rtpSecretsOn (ZrtpContext* ctx, char* c, char* s, int32_t verified ) ;
static void zrtp_handleGoClear(ZrtpContext* ctx) ;
static void zrtp_zrtpNegotiationFailed(ZrtpContext* ctx, int32_t severity, int32_t subCode ) ;
static void zrtp_zrtpNotSuppOther(ZrtpContext* ctx) ;
static void zrtp_synchEnter(ZrtpContext* ctx) ;
static void zrtp_synchLeave(ZrtpContext* ctx) ;
static void zrtp_zrtpAskEnrollment (ZrtpContext* ctx, char* info ) ;
static void zrtp_zrtpInformEnrollment(ZrtpContext* ctx, char* info ) ;
static void zrtp_signSAS(ZrtpContext* ctx, char* sas) ;
static int32_t zrtp_checkSASSignature (ZrtpContext* ctx, char* sas ) ;

/* The callback function structure for ZRTP */
static zrtp_Callbacks c_callbacks = {
    &zrtp_sendDataZRTP,
    &zrtp_activateTimer,
    &zrtp_cancelTimer,
    &zrtp_sendInfo,
    &zrtp_srtpSecretsReady,
    &zrtp_srtpSecretsOff,
    &zrtp_rtpSecretsOn,
    &zrtp_handleGoClear,
    &zrtp_zrtpNegotiationFailed,
    &zrtp_zrtpNotSuppOther,
    &zrtp_synchEnter,
    &zrtp_synchLeave,
    &zrtp_zrtpAskEnrollment,
    &zrtp_zrtpInformEnrollment,
    &zrtp_signSAS,
    &zrtp_checkSASSignature
};

/*
 * Here start with callback functions that support the ZRTP core
 */
static int32_t zrtp_sendDataZRTP (ZrtpContext* ctx, const uint8_t* data, int32_t length )
{
    return 0;
}

static int32_t zrtp_activateTimer (ZrtpContext* ctx, int32_t time)
{
    return 0;
}

static int32_t zrtp_cancelTimer(ZrtpContext* ctx)
{
    return 0;
}

static void zrtp_sendInfo (ZrtpContext* ctx, int32_t severity, int32_t subCode )
{
}

static int32_t zrtp_srtpSecretsReady (ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part )
{
    return 0;
}

static void zrtp_srtpSecretsOff (ZrtpContext* ctx, int32_t part )
{
}

static void zrtp_rtpSecretsOn (ZrtpContext* ctx, char* c, char* s, int32_t verified )
{
}

static void zrtp_handleGoClear(ZrtpContext* ctx)
{
}

static void zrtp_zrtpNegotiationFailed (ZrtpContext* ctx, int32_t severity, int32_t subCode )
{
}

static void zrtp_zrtpNotSuppOther(ZrtpContext* ctx)
{
}

static void zrtp_synchEnter(ZrtpContext* ctx)
{
}

static void zrtp_synchLeave(ZrtpContext* ctx)
{
}

static void zrtp_zrtpAskEnrollment(ZrtpContext* ctx, char* info )
{

}
static void zrtp_zrtpInformEnrollment(ZrtpContext* ctx, char* info )
{
}

static void zrtp_signSAS(ZrtpContext* ctx, char* sas)
{
}

static int32_t zrtp_checkSASSignature(ZrtpContext* ctx, char* sas )
{
    return 0;
}

int main(int argc, char *argv[])
{
    ZrtpContext* zrtpCtx;
    char* hh;
    char** names;
    
    zrtpCtx = zrtp_CreateWrapper ();
    zrtp_initializeZrtpEngine(zrtpCtx, &c_callbacks, "test", "test.zid", NULL);
    
    hh = zrtp_getHelloHash(zrtpCtx);
    if (hh != 0) 
    {
        printf("hh: %s\n", hh);
    }
    else
        printf("no hh");

    zrtp_InitializeConfig(zrtpCtx);
    names = zrtp_getAlgorithmNames(zrtpCtx, zrtp_HashAlgorithm);
    
    for (; *names; names++) {
        printf("name: %s\n", *names);
    }
    
    return 0;
}
#ifdef __cplusplus
}
#endif
