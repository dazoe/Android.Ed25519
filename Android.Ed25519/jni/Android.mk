LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := com_github_dazoe_android_Ed25519.c java_sha512.c ed25519/keypair.c ed25519/sign.c ed25519/open.c ed25519/crypto_verify_32.c ed25519/ge_scalarmult_base.c ed25519/ge_p3_tobytes.c ed25519/ge_p1p1_to_p3.c ed25519/ge_madd.c ed25519/ge_p1p1_to_p2.c ed25519/ge_precomp_0.c ed25519/ge_p3_0.c ed25519/ge_p3_dbl.c ed25519/ge_p2_dbl.c ed25519/ge_p3_to_p2.c ed25519/ge_frombytes.c ed25519/ge_double_scalarmult.c ed25519/ge_tobytes.c ed25519/ge_p3_to_cached.c ed25519/ge_add.c ed25519/ge_p2_0.c ed25519/ge_sub.c ed25519/ge_msub.c ed25519/fe_cmov.c ed25519/fe_copy.c ed25519/fe_0.c ed25519/fe_1.c ed25519/fe_isnegative.c ed25519/fe_tobytes.c ed25519/fe_mul.c ed25519/fe_invert.c ed25519/fe_sq.c ed25519/fe_sq2.c ed25519/fe_sub.c ed25519/fe_add.c ed25519/fe_neg.c ed25519/fe_frombytes.c ed25519/fe_pow22523.c ed25519/fe_isnonzero.c ed25519/sc_reduce.c ed25519/sc_muladd.c
LOCAL_MODULE := ed25519_android
include $(BUILD_SHARED_LIBRARY)
