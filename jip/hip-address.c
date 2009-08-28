/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipAddress.h"

#include <stddef.h>
#include <string.h>
#include <netdb.h>

#define HIT_LEN sizeof(struct in6_addr)

static jfieldID address_id;
static jmethodID init_id;

JNIEXPORT void JNICALL
Java_jip_HipAddress_nativeInit (JNIEnv *env, jclass cls)
{
    puts("HipAddress.nativeInit");
    fflush(stdout);
    address_id = (*env)->GetFieldID(env, cls, "address", "[B");
    init_id = (*env)->GetMethodID(env, cls, "<init>", "([B)V");
}

JNIEXPORT jobjectArray JNICALL
Java_jip_HipAddress_getAllByName (JNIEnv *env, jclass cls, jstring host)
{
    const jbyte *s = (*env)->GetStringUTFChars(env, host, NULL);
    struct addrinfo hints, *res, *ai;
    jbyteArray hit;
    int error, size, i;
    jobjectArray result;
    const jbyte *khost = NULL, *kport = NULL;
    int local = 0;
    printf("Hostname: <%s>\n", s);
    fflush(stdout);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_HIP;
    hints.ai_socktype = SOCK_STREAM;
    puts("getAllByName called");
    fflush(stdout);
    if (s == NULL || !strcmp(s, "") || !strncmp(s, "localhost", 9)) {
	local = 1;
	kport = "1";
    } else {
	khost = s;
    }
    printf("flags: %d\n", hints.ai_flags);
    fflush(stdout);

    error = get_hit_addrinfo(khost, kport, &hints, &res);

    printf("getAllByName() called, error=%d\n", error);
    fflush(stdout);
    if (error) {
	char buffer[256];
	jclass uh_ex_cls =
	    (*env)->FindClass(env, "java/net/UnknownHostException");
	snprintf(buffer, sizeof buffer, "get_hit_addrinfo() failed %d: %s",
					error, strerror(error));
	if (uh_ex_cls != NULL) {
	    (*env)->ThrowNew(env, uh_ex_cls, buffer);
	}
	return NULL;
    }
    printf("%p\n", res);
    fflush(stdout);
    (*env)->ReleaseStringUTFChars(env, host, s);
    size = 0;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
	size += 1;
	if (local) {
	    struct sockaddr_hip *addr = (struct sockaddr_hip *) ai->ai_addr;
	    addr->ship_port = 0;
	}
    }
    result = (*env)->NewObjectArray(env, size, cls, NULL);
    if (result == NULL) {
	return NULL;
    }
    for (ai = res, i = 0; ai != NULL; ai = ai->ai_next, i++) {
	struct sockaddr_hip *addr = (struct sockaddr_hip *) ai->ai_addr;

	hit = (*env)->NewByteArray(env, HIT_LEN);
	(*env)->SetByteArrayRegion(env, hit, 0, HIT_LEN, &addr->ship_hit);

	jobject hip_addr = (*env)->NewObject(env, cls, init_id, hit);

	(*env)->SetObjectArrayElement(env, result, i, hip_addr);
	(*env)->DeleteLocalRef(env, hip_addr);
    }
    freeaddrinfo(res);
    return result;
}

JNIEXPORT jobject JNICALL
Java_jip_HipAddress_getFromFile (JNIEnv *env, jclass cls, jstring file)
{
    const jbyte *s = (*env)->GetStringUTFChars(env, file, NULL);
    struct sockaddr_hip *addr;
    jbyteArray j_hit;
    jobject ret;
    int err = get_sockaddr_hip_from_key(s, &addr);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    char buffer[256];
	    snprintf(buffer, sizeof buffer,
		     "Could not load HIT from file %s", s);
	    (*env)->ThrowNew(env, io_ex_cls, buffer);
	}
	return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, file, s);

    j_hit = (*env)->NewByteArray(env, HIT_LEN);
    (*env)->SetByteArrayRegion(env, j_hit, 0, HIT_LEN, &addr->ship_hit);

    ret = (*env)->NewObject(env, cls, init_id, j_hit);
    free(addr);
    return ret;
}

/*
JNIEXPORT jbyteArray JNICALL
Java_jip_HipAddress_getMyHostIdentity (JNIEnv *env, jobject obj)
{
    struct sockaddr_eid my_eid;
    struct endpoint *endpoint;
    struct endpoint_hip *epoint;
    jbyteArray result;
    int err, size;
    my_eid.eid_family = PF_HIP;
    my_eid.eid_port = 0;
    my_eid.eid_val = (*env)->GetShortField(env, obj, value_id);
    err = getmyeidinfo(&my_eid, &endpoint, NULL);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Could not get my endpoint");
	}
	return NULL;
    }
    epoint = (struct endpoint_hip *) endpoint;
    size = epoint->length - offsetof(struct endpoint_hip, id);
    result = (*env)->NewByteArray(env, size);
    if (result != NULL) {
	(*env)->SetByteArrayRegion(env, result, 0, size,
				   (jbyte *) &epoint->id);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_jip_HipAddress_getPeerHostIdentity (JNIEnv *env, jobject obj)
{
    struct sockaddr_eid my_eid;
    struct endpoint *endpoint;
    struct endpoint_hip *epoint;
    jbyteArray result;
    int err, size;
    my_eid.eid_family = PF_HIP;
    my_eid.eid_port = 0;
    my_eid.eid_val = (*env)->GetShortField(env, obj, value_id);
    err = getpeereidinfo(&my_eid, &endpoint, NULL);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Could not get my endpoint");
	}
	return NULL;
    }
    epoint = (struct endpoint_hip *) endpoint;
    size = epoint->length - offsetof(struct endpoint_hip, id);
    result = (*env)->NewByteArray(env, size);
    if (result != NULL) {
	(*env)->SetByteArrayRegion(env, result, 0, size,
				   (jbyte *) &epoint->id);
    }
    return result;
}
*/
