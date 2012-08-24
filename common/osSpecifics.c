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


#include <stdint.h>
#include <common/osSpecifics.h>

#if defined(_WIN32) || defined(_WIN64)
# include <WinSock2.h>
#else
# include <netinet/in.h>
#endif

uint32_t zrtpNtohl (uint32_t net)
{
    return ntohl(net);
}

uint16_t zrtpNtohs (uint16_t net)
{
    return ntohs(net);
}

uint32_t zrtpHtonl (uint32_t host)
{
    return htonl(host);
}
uint16_t zrtpHtons (uint16_t host)
{
    return htons(host);
}

