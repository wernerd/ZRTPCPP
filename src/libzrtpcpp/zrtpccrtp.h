/*
  Copyright (C) 2006 Werner Dittmann

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Boston, MA 02111.
*/

#ifndef _ZRTPCCRTP_H_
#define _ZRTPCCRTP_H_

#include <ccrtp/rtp.h>
#include <libzrtpcpp/ZrtpQueue.h>

#ifdef  CCXX_NAMESPACES
namespace ost {
#endif


/**
 * @typedef SymmetricZRTPSession
 *
 * Uses one pair of sockets, (1) for RTP data and (2) for RTCP
 * transmission/reception.
 *
 * This session uses the ZrtpQueue instead of the AVPQueue. The ZrtpQueue
 * inherits from AVPQueue and adds support for ZRTP thus enabling
 * ad-hoc key negotiation to setup SRTP sessions.
 *
 * @short Symmetric UDP/IPv4 RTP session scheduled by one thread of execution.
 **/

typedef SingleThreadRTPSession<SymmetricRTPChannel,
                               SymmetricRTPChannel,
                               ZrtpQueue> SymmetricZRTPSession;

#ifdef   CCXX_NAMESPACES
}
#endif

#endif // _ZRTPCCRTP_H_