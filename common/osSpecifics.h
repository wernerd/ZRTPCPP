/*
  Copyright (C) 2012 Werner Dittmann

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

#ifndef _OSSPECIFICS_H_
#define _OSSPECIFICS_H_

/**
 * @file osSpecifics.h
 * @brief Some functions to adapt to OS and/or compiler specific handling
 * @defgroup GNU_ZRTP The GNU ZRTP C++ implementation
 * @{
 *
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#if defined(__cplusplus)
extern "C"
{
#endif
extern uint64_t zrtpGetTickCount();
extern uint32_t zrtpNtohl (uint32_t net);
extern uint16_t zrtpNtohs (uint16_t net);
extern uint32_t zrtpHtonl (uint32_t host);
extern uint16_t zrtpHtons (uint16_t host);

#if defined(__cplusplus)
}
#endif


/**
 * @}
 */
#endif
