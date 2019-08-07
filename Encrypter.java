package com.mycompany.android.tokenizer.util;


import android.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Locale;

import static android.util.Base64.NO_WRAP;
import static android.util.Base64.URL_SAFE;


public class Encrypter {

	private static final String PREFIX = "tw_";
	private static final String VERSION = "1";
	private static final String SEPARATOR = "$";

	private static final int IV_SIZE = 12;
	private static final int KEY_SIZE = 256;
	private static final int HEX_RADIX = 16;

	private PublicKey pubKey;
	private Cipher aesCipher;
	private Cipher rsaCipher;
	private SecureRandom secureRandom;
	private String publicKey;
	private String keyId;


	public Encrypter(String keyId, String publicKey) throws RuntimeException {
		this.keyId = keyId;
		this.publicKey = publicKey;

		secureRandom = new SecureRandom();
		String[] keyComponents = publicKey.split("\\|");

		// The bytes can be converted back to a public key object
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// Replace with proper logger
			System.out.println(e);
			return;
		}

		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
				new BigInteger(keyComponents[1].toLowerCase(Locale.US), HEX_RADIX),
				new BigInteger(keyComponents[0].toLowerCase(Locale.US), HEX_RADIX));

		try {
			pubKey = keyFactory.generatePublic(pubKeySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Problem reading public key: " + publicKey, e);
		}

		try {
			aesCipher = Cipher.getInstance("AES/CCM/NoPadding");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Problem instantiation AES Cipher Algorithm", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Problem instantiation AES Cipher Padding", e);
		}

		try {
			rsaCipher = Cipher.getInstance("RSA/None/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Problem instantiation RSA Cipher Algorithm", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Problem instantiation RSA Cipher Padding", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid public key: " + publicKey, e);
		}

	}

	public String encrypt(String plainText) throws RuntimeException {
		SecretKey aesKey = generateAESKey(KEY_SIZE);

		byte[] iv = generateIV(IV_SIZE);

		byte[] encrypted;
		try {
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
			// getBytes is UTF-8 on Android by default
			encrypted = aesCipher.doFinal(plainText.getBytes());
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Incorrect AES Block Size", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Incorrect AES Padding", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid AES Key", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException("Invalid AES Parameters", e);
		}

		byte[] result = new byte[iv.length + encrypted.length];
		// copy IV to result
		System.arraycopy(iv, 0, result, 0, iv.length);
		// copy encrypted to result
		System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

		byte[] encryptedAESKey;
		try {
			encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());
			return PREFIX + VERSION +
					SEPARATOR + keyId +
					SEPARATOR + Base64.encodeToString(encryptedAESKey, NO_WRAP | URL_SAFE) +
					SEPARATOR + Base64.encodeToString(result, NO_WRAP | URL_SAFE);

		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Incorrect RSA Block Size", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Incorrect RSA Padding", e);
		}
	}

	private SecretKey generateAESKey(int keySize) throws RuntimeException {
		KeyGenerator kgen;
		try {
			kgen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to get AES algorithm", e);
		}
		kgen.init(keySize);
		return kgen.generateKey();
	}

	/**
	 * Generate a random Initialization Vector (IV)
	 *
	 * @param ivSize
	 * @return the IV bytes
	 */
	private synchronized byte[] generateIV(int ivSize) {
		byte[] iv = new byte[ivSize];//generate random IV AES is always 16bytes, but in CCM mode this represents the NONCE
		secureRandom.nextBytes(iv);
		return iv;
	}

}