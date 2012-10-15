
LOCAL_PATH:=@CMAKE_SOURCE_DIR@/clients/tiviAndroid/jni/sqlite3

#####################################################################
#            build sqlite3                                            #
#####################################################################
include $(CLEAR_VARS)

LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_MODULE     :=sqlite3
LOCAL_SRC_FILES  :=sqlite3.c

include $(BUILD_STATIC_LIBRARY)
# include $(BUILD_SHARED_LIBRARY)


#####################################################################
#            build our code                    #
#####################################################################
#include $(CLEAR_VARS)
#LOCAL_C_INCLUDES := $(LOCAL_PATH)/sqlite-amalgamation-3070900
#LOCAL_MODULE:=sqlitetest
#LOCAL_SRC_FILES:=sqlite_test.c
#LOCAL_STATIC_LIBRARIES:=libsqlite3
#LOCAL_SHARED_LIBRARIES:=libsqlite3
#LOCAL_LDLIBS:=-llog -lm
#include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
