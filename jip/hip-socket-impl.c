/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipSocketImpl.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define CHECKINT(oper, message, text) do \
    if ((oper) < 0) { \
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException"); \
	if (io_ex_cls != NULL) { \
            char buffer[256]; \
            sprintf(buffer, "%s: %s", message, strerror(errno)); \
	    (*env)->ThrowNew(env, io_ex_cls, buffer); \
            text; \
	} \
    } while (0)

#define CHECK(oper, message) CHECKINT(oper, message, return)
#define CHECKVAL(oper, message, value) CHECKINT(oper, message, return value)

#define DEFINE_CONSTANT(name) do { \
    jfieldID fid = (*env)->GetStaticFieldID(env, cls, #name, "I"); \
    JAVA_##name = (*env)->GetStaticIntField(env, cls, fid); \
    } while (0)

#define HIT_LEN sizeof(struct in6_addr)

static jfieldID native_fd_id;
static jfieldID localport_id;
static jfieldID port_id;
static jfieldID ha_address_id;
static jmethodID dump_id;
static jmethodID set_address_id;
static jmethodID ia_get_host_address_id;

static jint JAVA_IP_MULTICAST_IF;
static jint JAVA_IP_MULTICAST_IF2;
static jint JAVA_IP_MULTICAST_LOOP;
static jint JAVA_IP_TOS;
static jint JAVA_SO_BINDADDR;
static jint JAVA_SO_BROADCAST;
static jint JAVA_SO_KEEPALIVE;
static jint JAVA_SO_LINGER;
static jint JAVA_SO_OOBINLINE;
static jint JAVA_SO_RCVBUF;
static jint JAVA_SO_REUSEADDR;
static jint JAVA_SO_SNDBUF;
static jint JAVA_SO_TIMEOUT;
static jint JAVA_TCP_NODELAY;

static int
get_boolean (JNIEnv *env, jobject obj)
{
    int result = -1;
    jclass cls = (*env)->GetObjectClass(env, obj);
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "booleanValue", "()Z");
	if (mid != NULL) {
	    result = (*env)->CallBooleanMethod(env, obj, mid);
	    if ((*env)->ExceptionOccurred(env)) {
		result = -1;
	    }
	}
    }
    return result;
}

static int
get_integer (JNIEnv *env, jobject obj)
{
    int result = -1;
    jclass cls = (*env)->GetObjectClass(env, obj);
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "intValue", "()I");
	if (mid != NULL) {
	    result = (*env)->CallIntMethod(env, obj, mid);
	    if ((*env)->ExceptionOccurred(env)) {
		result = -1;
	    }
	}
    }
    return result;
}

static jobject
create_boolean (JNIEnv *env, jboolean value)
{
    jobject result = NULL;
    jclass cls = (*env)->FindClass(env, "java/lang/Boolean");
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "(Z)V");
	if (mid != NULL) {
	    result = (*env)->NewObject(env, cls, mid, value);
	}
    }
    return result;
}

static jobject
create_integer (JNIEnv *env, jint value)
{
    jobject result = NULL;
    jclass cls = (*env)->FindClass(env, "java/lang/Integer");
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "(I)V");
	if (mid != NULL) {
	    result = (*env)->NewObject(env, cls, mid, value);
	}
    }
    return result;
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_nativeInit (JNIEnv *env, jclass cls)
{
    jclass ia_cls, ha_cls;
    puts("HipSocketImpl.nativeInit");
    fflush(stdout);
    ia_cls = (*env)->FindClass(env, "java/net/InetAddress");
    if (ia_cls == NULL) {
	return;
    }
    ha_cls = (*env)->FindClass(env, "jip/HipAddress");
    if (ha_cls == NULL) {
	return;
    }
    native_fd_id = (*env)->GetFieldID(env, cls, "native_fd", "I");
    localport_id = (*env)->GetFieldID(env, cls, "localport", "I");
    port_id = (*env)->GetFieldID(env, cls, "port", "I");
    ha_address_id = (*env)->GetFieldID(env, ha_cls, "address", "[B");
    dump_id = (*env)->GetMethodID(env, cls, "dump", "()V");
    set_address_id = (*env)->GetMethodID(env, cls, "setAddress", "([B)V");
    ia_get_host_address_id = (*env)->GetMethodID(env, ia_cls, "getHostAddress",
						 "()Ljava/lang/String;");
    DEFINE_CONSTANT(IP_MULTICAST_IF);
    DEFINE_CONSTANT(IP_MULTICAST_IF2);
    DEFINE_CONSTANT(IP_MULTICAST_LOOP);
    DEFINE_CONSTANT(IP_TOS);
    DEFINE_CONSTANT(SO_BINDADDR);
    DEFINE_CONSTANT(SO_BROADCAST);
    DEFINE_CONSTANT(SO_KEEPALIVE);
    DEFINE_CONSTANT(SO_LINGER);
    DEFINE_CONSTANT(SO_OOBINLINE);
    DEFINE_CONSTANT(SO_RCVBUF);
    DEFINE_CONSTANT(SO_REUSEADDR);
    DEFINE_CONSTANT(SO_SNDBUF);
    DEFINE_CONSTANT(SO_TIMEOUT);
    DEFINE_CONSTANT(TCP_NODELAY);
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_create (JNIEnv *env, jobject obj, jboolean is_stream)
{
    int fd = socket(PF_HIP, is_stream ? SOCK_STREAM : SOCK_DGRAM, 0);
    printf("Create: %d %d\n", fd, is_stream);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(fd, "Cannot create socket");
    (*env)->SetIntField(env, obj, native_fd_id, fd);
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_bind (JNIEnv *env, jobject obj, jobject addr, jint port)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    struct sockaddr_hip sock_addr;
    struct in6_addr hit;
    jbyteArray j_hit;
    jfieldID hit_id;
    jclass cls;
    printf("Bind: <%d> %d\n", port, fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);

    memset(&hit, 0, sizeof(hit));
    cls = (*env)->GetObjectClass(env, addr);
    hit_id = (*env)->GetFieldID(env, cls, "address", "[B");
    j_hit = (*env)->GetObjectField(env, addr, hit_id);
    (*env)->GetByteArrayRegion(env, j_hit, 0, HIT_LEN, &hit);

    memset(&sock_addr, 0, sizeof(sock_addr));
    memcpy(&sock_addr.ship_hit, &hit, sizeof(hit));
    sock_addr.ship_family = PF_HIP;
    sock_addr.ship_port = htons(port);

    CHECK(bind(fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)),
	  "Bind failed\n");
    (*env)->SetIntField(env, obj, localport_id, port);
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_connect (JNIEnv *env, jobject obj, jobject addr,
				jint port)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    struct sockaddr_hip sock_addr;
    struct in6_addr hit;
    jbyteArray j_hit;
    jfieldID hit_id;
    jclass cls;
    printf("Connect: <%d> %d\n", port, fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);

    cls = (*env)->GetObjectClass(env, addr);
    hit_id = (*env)->GetFieldID(env, cls, "address", "[B");
    j_hit = (*env)->GetObjectField(env, addr, hit_id);
    (*env)->GetByteArrayRegion(env, j_hit, 0, HIT_LEN, &hit);

    memset(&sock_addr, 0, sizeof(sock_addr));
    memcpy(&sock_addr.ship_hit, &hit, sizeof(hit));
    sock_addr.ship_family = PF_HIP;
    sock_addr.ship_port = htons(port);

    CHECK(connect(fd, (struct sockaddr *) &sock_addr, sizeof sock_addr),
	  "Connect failed");
    (*env)->SetIntField(env, obj, port_id, port);
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_listen (JNIEnv *env, jobject obj, jint backlog)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Listen: %d %d\n", fd, backlog);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(listen(fd, backlog), "Listen failed");
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_accept (JNIEnv *env, jobject obj, jobject impl)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    int s;
    struct sockaddr_hip local_addr, remote_addr;
    socklen_t local_len = sizeof(local_addr), remote_len = sizeof(remote_addr);
    printf("Accept: %d\n", fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    s = accept(fd, (struct sockaddr *) &remote_addr, &remote_len);
    CHECK(s, "Accept failed");
    CHECK(getsockname(s, (struct sockaddr *) &local_addr, &local_len),
	  "Sockname failed");
    (*env)->SetIntField(env, impl, native_fd_id, s);
    (*env)->SetIntField(env, impl, localport_id, ntohs(local_addr.ship_port));
    (*env)->SetIntField(env, impl, port_id, ntohs(remote_addr.ship_port));
}

JNIEXPORT jint JNICALL
Java_jip_HipSocketImpl_available (JNIEnv *env, jobject obj)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    int value;
    printf("Available: %d\n", fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECKVAL(ioctl(fd, FIONREAD, &value), "Available failed", -1);
    return value;
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_close (JNIEnv *env, jobject obj)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Close: %d\n", fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(close(fd), "Close failed");
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_sendUrgentData (JNIEnv *env, jobject obj, jint data)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    char c = data & 0xFF;
    printf("Urgent: %d %d\n", fd, data);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(send(fd, &c, 1, MSG_OOB), "Urgent failed");
}

JNIEXPORT jobject JNICALL
Java_jip_HipSocketImpl_getOption (JNIEnv *env, jobject obj, jint id)
{
    jobject result = NULL;
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Get option: %d %d\n", fd, id);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    if (id == JAVA_TCP_NODELAY) {
	int optval;
	int optlen = sizeof optval;
	CHECKVAL(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, &optlen),
		 "Get option failed", NULL);
	if (optval) {
	    result = create_boolean(env, JNI_TRUE);
	} else {
	    result = create_boolean(env, JNI_FALSE);
	}
    } else if (id == JAVA_SO_TIMEOUT) {
	struct timeval optval;
	int optlen = sizeof optval;
	CHECKVAL(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &optval, &optlen),
		 "Get option failed", NULL);
	result = create_integer(env, optval.tv_sec * 1000
				+ optval.tv_usec / 1000);
    } else {
	jclass ex_cls = (*env)->FindClass(env, "java/net/SocketException");
	if (ex_cls != NULL) {
	    char buffer[256];
	    sprintf(buffer, "Unrecognized option: %d", id);
	    (*env)->ThrowNew(env, ex_cls, buffer);
	}
    }
    return result;
}

JNIEXPORT void JNICALL
Java_jip_HipSocketImpl_setOption (JNIEnv *env, jobject obj, jint id,
				  jobject value)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Set option: %d %d\n", fd, id);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    if (id == JAVA_TCP_NODELAY) {
	int optval = get_boolean(env, value);
	if (optval == -1) {
	    return;
	}
	CHECK(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof optval),
	      "Set option failed");
    } else if (id == JAVA_SO_TIMEOUT) {
	int time = get_integer(env, value);
	struct timeval optval;
	if (time == -1) {
	    return;
	}
	optval.tv_sec = time / 1000;
	optval.tv_usec = time % 1000;
	CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof optval),
	      "Set option failed");
    } else {
	jclass ex_cls = (*env)->FindClass(env, "java/net/SocketException");
	if (ex_cls != NULL) {
	    char buffer[256];
	    sprintf(buffer, "Unrecognized option: %d", id);
	    (*env)->ThrowNew(env, ex_cls, buffer);
	}
    }
}
