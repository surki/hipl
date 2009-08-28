/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipSocket.h"

JNIEXPORT void JNICALL
Java_jip_HipSocket_klugeAccept (JNIEnv *env, jobject obj)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID post_accept_id = (*env)->GetMethodID(env, cls, "postAccept",
						   "()V");
    if (post_accept_id == NULL) {
	jclass ex_cls = (*env)->FindClass(env,
					  "java/lang/IllegalStateException");
	if (ex_cls != NULL) {
	    (*env)->ThrowNew(env, ex_cls, "Sun Java implementation required");
	    return;
	}
    }
    (*env)->CallVoidMethod(env, obj, post_accept_id);
}
