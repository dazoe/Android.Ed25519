#include "com_github_dazoe_android_Ed25519.h"
#include "ed25519/ed25519.h"

// void sha512(const unsigned char* m, size_t n, unsigned char* md) {
// 	JNIEnv *env = _env;
// 	if (env) {
// 		jclass cls = (*env)->FindClass(env, "com/github/dazoe/android/Ed25519");
// 		jmethodID mid = (*env)->GetStaticMethodID(env, cls, "Sha512", "([B)[B");
// 		if (mid == 0) return;
// 		jbyteArray data = (*env)->NewByteArray(env, n);
// 		(*env)->SetByteArrayRegion(env, data, 0, n, (jbyte*)m);
// 		jbyteArray resultA = (jbyteArray)(*env)->CallStaticObjectMethod(env, cls, mid, data);
// 		//Somehow free jbyteArray data here?? TODO!
// 		if (resultA == NULL) return;
// 		unsigned char *result = (unsigned char*) (*env)->GetByteArrayElements(env, resultA, NULL);
// 		int len = (*env)->GetArrayLength(env, resultA);
// 		int i;
// 		for (i = 0; i < len; i++) {
// 			md[i] = result[i];
// 		}
// 		(*env)->ReleaseByteArrayElements(env, resultA, (jbyte*)result, JNI_ABORT);
// 	}
// }

// void sha512(const unsigned char* m, size_t n, unsigned char* md) {
// 	// SHA512_CTX ctx;
// 	// SHA512_Init(&ctx);
// 	JNIEnv *env = _env;
// 	if (env) {
// 		jclass cls = (*env)->FindClass(env, "com/github/dazoe/android/Ed25519");
// 		jmethodID mid = (*env)->GetStaticMethodID(env, cls, "SHA512_Init", "()Ljava/security/MessageDigest;");
// 		if (mid == 0) return;
// 		jobject obj = (jobject)(*env)->CallStaticObjectMethod(env, cls, mid);
// 		if (obj == NULL) return;
// 		mid = (*env)->GetStaticMethodID(env, cls, "SHA512_Update", "(Ljava/security/MessageDigest;[B)V");
// 		if (mid == 0) return;
// 		jbyteArray data = (*env)->NewByteArray(env, n);
// 		(*env)->SetByteArrayRegion(env, data, 0, n, (jbyte*)m);
// 		(*env)->CallStaticVoidMethod(env, cls, mid, obj, data);
// 		mid = (*env)->GetStaticMethodID(env, cls, "SHA512_Final", "(Ljava/security/MessageDigest;)[B");
// 		jbyteArray resultA = (jbyteArray)(*env)->CallStaticObjectMethod(env, cls, mid, obj);
// 		//Somehow free jbyteArray data here?? TODO!
// 		if (resultA == NULL) return;
// 		unsigned char *result = (unsigned char*) (*env)->GetByteArrayElements(env, resultA, NULL);
// 		int len = (*env)->GetArrayLength(env, resultA);
// 		int i;
// 		for (i = 0; i < len; i++) {
// 			md[i] = result[i];
// 		}
// 		(*env)->ReleaseByteArrayElements(env, resultA, (jbyte*)result, JNI_ABORT);
// 	}
// }

JNIEXPORT jbyteArray JNICALL Java_com_github_dazoe_android_Ed25519_PrivateKeyFromSeedN(JNIEnv *env, jclass cls, jbyteArray seed) {
	_env = env;
	unsigned char* seedData = (unsigned char*)(*env)->GetByteArrayElements(env, seed, NULL);
	unsigned char pk[32];
	unsigned char sk[64];
	int i;
	for (i = 0; i < 32; i++) {
		sk[i] = seedData[i];
	}
	(*env)->ReleaseByteArrayElements(env, seed, (jbyte*)seedData, JNI_ABORT);
	crypto_sign_keypair(pk, sk);
	jbyteArray result = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, result, 0, 64, (jbyte*)sk);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_github_dazoe_android_Ed25519_PublicKeyFromSeedN(JNIEnv *env, jclass cls, jbyteArray seed) {
	_env = env;
	unsigned char* seedData = (unsigned char*)(*env)->GetByteArrayElements(env, seed, NULL);
	unsigned char pk[32];
	unsigned char sk[64];
	int i;
	for (i = 0; i < 32; i++) {
		sk[i] = seedData[i];
	}
	(*env)->ReleaseByteArrayElements(env, seed, (jbyte*)seedData, JNI_ABORT);
	crypto_sign_keypair(pk, sk);
	jbyteArray result = (*env)->NewByteArray(env, 32);
	(*env)->SetByteArrayRegion(env, result, 0, 32, (jbyte*)pk);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_github_dazoe_android_Ed25519_SignN(JNIEnv *env, jclass cls, jbyteArray message, jbyteArray privateKey) {
	_env = env;
	unsigned long long messageLen = (*env)->GetArrayLength(env, message);
	unsigned char* messageData = (unsigned char*)(*env)->GetByteArrayElements(env, message, NULL);
	unsigned char* privateKeyData = (unsigned char*)(*env)->GetByteArrayElements(env, privateKey, NULL);
	unsigned long long signatureMessageLen = 64 + messageLen;
	unsigned char signatureMessageData[signatureMessageLen];
	crypto_sign(signatureMessageData, &signatureMessageLen, messageData, messageLen, privateKeyData);
	(*env)->ReleaseByteArrayElements(env, message, (jbyte*)messageData, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, privateKey, (jbyte*)privateKeyData, JNI_ABORT);
	jbyteArray signature = (*env)->NewByteArray(env, 64);
	(*env)->SetByteArrayRegion(env, signature, 0, 64, (jbyte*)signatureMessageData);
	return signature;
}

JNIEXPORT jint JNICALL Java_com_github_dazoe_android_Ed25519_VerifyN(JNIEnv *env, jclass cls, jbyteArray message, jbyteArray signature, jbyteArray publicKey) {
	_env = env;
	size_t messageLen = (*env)->GetArrayLength(env, message);
	unsigned char* signatureData = (unsigned char*)(*env)->GetByteArrayElements(env, signature, NULL);
	unsigned char* messageData = (unsigned char*)(*env)->GetByteArrayElements(env, message, NULL);
	unsigned char* publicKeyData = (unsigned char*)(*env)->GetByteArrayElements(env, publicKey, NULL);
	int result = crypto_sign_verify(signatureData, messageData, messageLen, publicKeyData);
	(*env)->ReleaseByteArrayElements(env, signature, (jbyte*)signatureData, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, message, (jbyte*)messageData, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, publicKey, (jbyte*)publicKeyData, JNI_ABORT);
	return result;
}