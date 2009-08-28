#include "jip_NativeInputStream.h"
#include "jip_NativeOutputStream.h"

#include <unistd.h>

static jfieldID input_fd_id;
static jfieldID output_fd_id;

JNIEXPORT void JNICALL
Java_jip_NativeInputStream_nativeInit (JNIEnv *env, jclass cls)
{
    input_fd_id = (*env)->GetFieldID(env, cls, "fd", "I");
}

JNIEXPORT jint JNICALL
Java_jip_NativeInputStream_internalRead (JNIEnv *env,
							jobject obj,
							jbyteArray b, int off,
							int len)
{
    int n;
    int fd = (*env)->GetIntField(env, obj, input_fd_id);
    jbyte *bytes = (*env)->GetByteArrayElements(env, b, NULL);
    if (bytes == NULL) {
	return -1;
    }
    n = read(fd, bytes + off, len);
    (*env)->ReleaseByteArrayElements(env, b, bytes, 0);
    if (n == 0) {
	return -1;
    }
    return n;
}

JNIEXPORT void JNICALL
Java_jip_NativeOutputStream_nativeInit (JNIEnv *env, jclass cls)
{
    output_fd_id = (*env)->GetFieldID(env, cls, "fd", "I");
}

JNIEXPORT void JNICALL
Java_jip_NativeOutputStream_internalWrite (JNIEnv *env,
							  jobject obj,
							  jbyteArray b,
							  int off, int len)
{
    int n;
    int fd = (*env)->GetIntField(env, obj, output_fd_id);
    jbyte *bytes = (*env)->GetByteArrayElements(env, b, NULL);
    if (bytes == NULL) {
	return;
    }
    n = write(fd, bytes + off, len);
    (*env)->ReleaseByteArrayElements(env, b, bytes, 0);
    if (n < 0) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Write failed");
	}
    }
}
