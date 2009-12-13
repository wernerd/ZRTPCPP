########### next target ###############

add_executable(zrtptest zrtptest.cpp)
target_link_libraries(zrtptest zrtpcpp)

########### next target ###############

add_executable(zrtptestMulti zrtptestMulti.cpp)
target_link_libraries(zrtptestMulti zrtpcpp)

########### install files ###############
# None

########### source distribution ########
include(SourceDistribution)
src_distribution_init()
add_src_dist_files(zrtptestMulti.cpp zrtptest.cpp)
