# - a gcrypt-config module for CMake
#
# Usage:
#   gcrypt_check(<PREFIX> [REQUIRED] <MODULE> [ALGORITHM]*)
#     checks if libgcrypt is vaialable and support specified algorithms
#
# When the 'REQUIRED' argument was set, macros will fail with an error
# when module(s) could not be found
#
# It sets the following variables:
#   GCRYPT_CONFIG_FOUND         ... true if pkg-config works on the system
#   GCRYPT_CONFIG_EXECUTABLE    ... pathname of the pkg-config program
#   <PREFIX>_FOUND              ... set to 1 if libgcrypt exist
#
# For the following variables two sets of values exist; first one is the
# common one and has the given PREFIX. 
#
#   <PREFIX>_LIBRARIES      ... only the libraries (w/o the '-l')
#   <PREFIX>_LIBRARY_DIRS   ... the paths of the libraries (w/o the '-L')
#   <PREFIX>_LDFLAGS        ... all required linker flags
#   <PREFIX>_LDFLAGS_OTHER  ... all other linker flags
#   <PREFIX>_INCLUDE_DIRS   ... the '-I' preprocessor flags (w/o the '-I')
#   <PREFIX>_CFLAGS         ... all required cflags
#   <PREFIX>_CFLAGS_OTHER   ... the other compiler flags
#
# A <MODULE> parameter can have the following formats:
#   {MODNAME}            ... matches any version
#   {MODNAME}>={VERSION} ... at least version <VERSION> is required
#   {MODNAME}={VERSION}  ... exactly version <VERSION> is required
#   {MODNAME}<={VERSION} ... modules must not be newer than <VERSION>
#
# Examples
#   gcrypt_check (GCRYPT gcrypt)
#
#   gcrypt_check (GCRYPT  gcrypt>=1.10)
#     requires at least version 1.10 of gcrypt and defines e.g.
#       GCRYPT_VERSION=1.4.1
#

# Copyright (C) 2006 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
#
# Redistribution and use, with or without modification, are permitted
# provided that the following conditions are met:
# 
#    1. Redistributions must retain the above copyright notice, this
#       list of conditions and the following disclaimer.
#    2. The name of the author may not be used to endorse or promote
#       products derived from this software without specific prior
#       written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


### Common stuff ####
set(GCR_CONFIG_VERSION 1)
set(GCR_CONFIG_FOUND   0)

find_program(GCR_CONFIG_EXECUTABLE NAMES libgcrypt-config --version DOC "libgcrypt-config executable")
mark_as_advanced(GCR_CONFIG_EXECUTABLE)

if(GCR_CONFIG_EXECUTABLE)
  set(GCR_CONFIG_FOUND 1)
endif(GCR_CONFIG_EXECUTABLE)


# Unsets the given variables
macro(_gcrconfig_unset var)
  set(${var} "" CACHE INTERNAL "")
endmacro(_gcrconfig_unset)

macro(_gcrconfig_set var value)
  set(${var} ${value} CACHE INTERNAL "")
endmacro(_gcrconfig_set)

# Invokes libgcrypt-config, cleans up the result and sets variables
macro(_gcrconfig_invoke _gcrlist _prefix _varname _regexp)
  set(_gcrconfig_invoke_result)

  execute_process(
    COMMAND ${GCR_CONFIG_EXECUTABLE} ${ARGN}
    OUTPUT_VARIABLE _gcrconfig_invoke_result
    RESULT_VARIABLE _gcrconfig_failed)

  if (_gcrconfig_failed)
    set(_gcrconfig_${_varname} "")
    _gcrconfig_unset(${_prefix}_${_varname})
  else(_gcrconfig_failed)
    string(REGEX REPLACE "[\r\n]"                  " " _gcrconfig_invoke_result "${_gcrconfig_invoke_result}")
    string(REGEX REPLACE " +$"                     ""  _gcrconfig_invoke_result "${_gcrconfig_invoke_result}")

    if (NOT ${_regexp} STREQUAL "")
      string(REGEX REPLACE "${_regexp}" " " _gcrconfig_invoke_result "${_gcrconfig_invoke_result}")
    endif(NOT ${_regexp} STREQUAL "")

    separate_arguments(_gcrconfig_invoke_result)

    #message(STATUS "  ${_varname} ... ${_gcrconfig_invoke_result}")
    set(_gcrconfig_${_varname} ${_gcrconfig_invoke_result})
    _gcrconfig_set(${_prefix}_${_varname} "${_gcrconfig_invoke_result}")
  endif(_gcrconfig_failed)
endmacro(_gcrconfig_invoke)

macro(_gcrconfig_invoke_dyn _gcrlist _prefix _varname cleanup_regexp)
  _gcrconfig_invoke("${_gcrlist}" ${_prefix}        ${_varname} "${cleanup_regexp}" ${ARGN})
endmacro(_gcrconfig_invoke_dyn)

# Splits given arguments into options and a package list
macro(_gcrconfig_parse_options _result _is_req)
  set(${_is_req} 0)
  
  foreach(_gcr ${ARGN})
    if (_gcr STREQUAL "REQUIRED")
      set(${_is_req} 1)
    endif (_gcr STREQUAL "REQUIRED")
  endforeach(_gcr ${ARGN})

  set(${_result} ${ARGN})
  list(REMOVE_ITEM ${_result} "REQUIRED")
endmacro(_gcrconfig_parse_options)

###
macro(_gcr_check_modules_internal _is_required _is_silent _prefix)
  _gcrconfig_unset(${_prefix}_FOUND)
  _gcrconfig_unset(${_prefix}_VERSION)
  _gcrconfig_unset(${_prefix}_PREFIX)
  _gcrconfig_unset(${_prefix}_LIBDIR)
  _gcrconfig_unset(${_prefix}_LIBRARIES)
  _gcrconfig_unset(${_prefix}_CFLAGS)
  _gcrconfig_unset(${_prefix}_ALGORITHMS)

  # create a better addressable variable of the modules and calculate its size
  set(_gcr_check_modules_list ${ARGN})
  list(LENGTH _gcr_check_modules_list _gcr_check_modules_cnt)

  if(GCR_CONFIG_EXECUTABLE)
    # give out status message telling checked module
    if (NOT ${_is_silent})
        message(STATUS "checking for module '${_gcr_check_modules_list}'")
    endif(NOT ${_is_silent})
    
    # iterate through module list and check whether they exist and match the required version
    foreach (_gcr_check_modules_gcr ${_gcr_check_modules_list})

      # check whether version is given
      if (_gcr_check_modules_gcr MATCHES ".*(>=|=|<=).*")
        string(REGEX REPLACE "(.*[^><])(>=|=|<=)(.*)" "\\1" _gcr_check_modules_gcr_name "${_gcr_check_modules_gcr}")
        string(REGEX REPLACE "(.*[^><])(>=|=|<=)(.*)" "\\2" _gcr_check_modules_gcr_op   "${_gcr_check_modules_gcr}")
        string(REGEX REPLACE "(.*[^><])(>=|=|<=)(.*)" "\\3" _gcr_check_modules_gcr_ver  "${_gcr_check_modules_gcr}")
      else(_gcr_check_modules_gcr MATCHES ".*(>=|=|<=).*")
        set(_gcr_check_modules_gcr_name "${_gcr_check_modules_gcr}")
        set(_gcr_check_modules_gcr_op)
        set(_gcr_check_modules_gcr_ver)
      endif(_gcr_check_modules_gcr MATCHES ".*(>=|=|<=).*")

      set(_gcr_check_prefix "${_prefix}")
        
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" VERSION    ""   --version )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" PREFIX     ""   --prefix )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" LIBRARIES  ""   --libs )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" CFLAGS     ""   --cflags )
      _gcrconfig_invoke(${_gcr_check_modules_gcr_name} "${_gcr_check_prefix}" ALGORITHMS ""   --algorithms )

        message(STATUS "  found ${_gcr_check_modules_gcr}, version ${_gcrconfig_VERSION}")
      # handle the operands
      if (_gcr_check_modules_gcr_op STREQUAL ">=")
        list(APPEND _gcr_check_modules_exist_query --atleast-version)
      endif(_gcr_check_modules_gcr_op STREQUAL ">=")

      if (_gcr_check_modules_gcr_op STREQUAL "=")
        list(APPEND _gcr_check_modules_exist_query --exact-version)
      endif(_gcr_check_modules_gcr_op STREQUAL "=")
      
      if (_gcr_check_modules_gcr_op STREQUAL "<=")
        list(APPEND _gcr_check_modules_exist_query --max-version)
      endif(_gcr_check_modules_gcr_op STREQUAL "<=")

    endforeach(_gcr_check_modules_gcr)
    _pkgconfig_set(${_prefix}_FOUND 1)

  else(GCR_CONFIG_EXECUTABLE)
    if (${_is_required})
      message(SEND_ERROR "libgcrypt-config tool not found")
    endif (${_is_required})
  endif(GCR_CONFIG_EXECUTABLE)
endmacro(_gcr_check_modules_internal)

###
### User visible macros start here
###

###
macro(gcr_check _prefix _module0)
  # check cached value
  if (NOT DEFINED __gcr_config_checked_${_prefix} OR __gcr_config_checked_${_prefix} LESS ${GCR_CONFIG_VERSION} OR NOT ${_prefix}_FOUND)
    _gcrconfig_parse_options   (_gcr_modules _gcr_is_required "${_module0}" ${ARGN})
    _gcr_check_modules_internal("${_gcr_is_required}" 0 "${_prefix}" ${_gcr_modules})

    _gcrconfig_set(__gcr_config_checked_${_prefix} ${GCR_CONFIG_VERSION})
  endif(NOT DEFINED __gcr_config_checked_${_prefix} OR __gcr_config_checked_${_prefix} LESS ${GCR_CONFIG_VERSION} OR NOT ${_prefix}_FOUND)
endmacro(gcr_check)

###

### Local Variables:
### mode: cmake
### End:
