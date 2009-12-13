##  Copyright (C) 2006 Werner Dittmann.
##
## This file is free software; as a special exception the author gives
## unlimited permission to copy and/or distribute it, with or without
## modifications, as long as this notice is preserved.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

include(SourceDistribution)
src_distribution_init()
file(GLOB distribute RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.h)
add_src_dist_files(${distribute})

########### install files ###############

# install(FILES  DESTINATION include/libzrtpcpp/crypto)
