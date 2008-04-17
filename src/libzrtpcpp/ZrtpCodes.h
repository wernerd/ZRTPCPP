/*
  Copyright (C) 2006-2008 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ZRTPCODES_H_
#define _ZRTPCODES_H_
/**
 * This enum defines the information message severity.
 *
 * The ZRTP implementation issues information messages to inform the user
 * about ongoing processing, unusual behavior, or alerts in case of severe
 * problems. The severity levels and their meaning are:
 *
 * <dl>
 * <dt>Info</dt> <dd>keeps the user informed about ongoing processing and
 *     security setup.
 * </dd>
 * <dt>Warning</dt> <dd>is an information about some security issues, e.g. if
 *     an AES 256 encryption is request but only DH 3072 as public key scheme
 *     is supported. ZRTP will establish a secure session (SRTP).
 * </dd>
 * <dt>Error</dt> <dd>is used if an error occured during ZRTP protocol usage. For
 *     example if an unknown or unsupported alogrithm is offerd. In case of
 *     <em>Error</em> ZRTP will <b>not</b> establish a secure session.
 * </dd>
 * <dt>Alert</dt> <dd>shows a real security problem. This probably falls into
 *     a <em>MitM</em> category. ZRTP of course will <b>not</b> establish a
 *     secure session.
 * </dd>
 * </dl>
 *
 */
enum MessageSeverity {
    Info = 1,
    Warning,
    Error,
    Alert
};


#endif
