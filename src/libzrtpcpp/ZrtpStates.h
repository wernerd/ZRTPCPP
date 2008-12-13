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

#ifndef _ZRTPSTATES_H_
#define _ZRTPSTATES_H_


#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/**
 * Implement a simple state handling.
 *
 * This class provides functions that manage the states and the event handler
 * functions. Its a very simple implementation.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpStateClass;
/**
 * This structure hold the state name as enum (int) number and the pointer to
 * the functions that handles the various triggers that can occur in a state.
 */
typedef struct  {
    int32_t stateName;
    void (ZrtpStateClass::* handler)(void);
} state_t;

class ZrtpStates {
 public:

    ZrtpStates(state_t* const zstates,
	       const int32_t numStates,
	       const int32_t initialState):
	numStates(numStates), states(zstates), state(initialState) {}

    int32_t processEvent(ZrtpStateClass& zsc) {
	// fprintf(stdout, "ZrtpStates::processEvent, state: %d\n", state);
	(zsc.*states[state].handler)();
	return 0;	// hmm...maybe we can do more??  but handlers are void...
    }

    bool inState(const int32_t s) { return ((s == state)); }

    void nextState(int32_t s)        { state = s; }

 private:
    const int32_t numStates;
    const state_t* states;
    int32_t  state;

    ZrtpStates();
};

#endif	//ZRTPSTATES

