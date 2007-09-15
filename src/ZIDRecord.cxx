/*
  Copyright (C) 2006-2007 Werner Dittmann

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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZIDRecord.h>

void ZIDRecord::setNewRs1(const unsigned char *data) {

  // shift RS1 data and flag into RS2
  memcpy(record.rs2Data, record.rs1Data, RS_LENGTH);
  record.rs2Valid = record.rs1Valid;

  // set new RS1 data
  memcpy(record.rs1Data, data, RS_LENGTH);
  record.rs1Valid = 1;
  // copy the SAS verified flag to new record as well
  if (record.rs2Valid & SASVerified) {
      record.rs1Valid |= SASVerified;
  }
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
