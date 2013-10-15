package com.github.dazoe.android;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import android.util.Log;

public class Ed25519 {
	private native static byte[] PrivateKeyFromSeedN(byte[] seed);
	private native static byte[] PublicKeyFromSeedN(byte[] privateKey);
	private native static byte[] SignN(byte[] message, byte[] privateKey);
	private native static int VerifyN(byte[] message, byte[] signature, byte[] publicKey);

	private static MessageDigest SHA512_Init() {
		Log.d("Ed25519", "SHA512_Init");
		try {
			return MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	private static void SHA512_Update(MessageDigest md, byte[] data) {
		Log.d("Ed25519", "SHA512_Update");
		md.update(data);
	}
	private static byte[] SHA512_Final(MessageDigest md) {
		Log.d("Ed25519", "SHA512_Final");
		return md.digest();
	}

	public static byte[] PrivateKeyFromSeed(byte[] seed) throws Exception {
		if (seed.length != 32) throw new Exception("Invalid seed length, must be 32 bytes");
		Log.d("Ed25519", "1");
		return PrivateKeyFromSeedN(seed);
	}
	public static byte[] PublicKeyFromSeed(byte[] seed) throws Exception {
		if (seed.length != 32) throw new Exception("Invalid seed length, must be 32 bytes");
		return PublicKeyFromSeedN(seed);
	}
	public static byte[] PublicKeyFromPrivateKey(byte[] privateKey) throws Exception {
		if (privateKey.length != 64) throw new Exception("Invalid privateKey length, must be 64 bytes");
		return Arrays.copyOfRange(privateKey, 32, 64);
	}
	public static byte[] Sign(byte[] message, byte[] privateKey) throws Exception {
		if (privateKey.length != 64) throw new Exception("Invalid privateKey length, must be 64 bytes");
		return SignN(message, privateKey);
	}
	public static int Verify(byte[] message, byte[] signature, byte[] publicKey) throws Exception {
		if (publicKey.length != 32) throw new Exception("Invalid publicKey length, must be 32 bytes");
		if (signature.length != 64) return -1;
		return VerifyN(message, signature, publicKey);
	}
	
	static {
		System.loadLibrary("ed25519_android");
	}
}
