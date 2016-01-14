package com.polytech;


import java.security.*;
import java.util.Arrays;

import javax.crypto.*;

import java.io.*;

public class Entity {

	// keypair
		public PublicKey thePublicKey;
		private PrivateKey thePrivateKey;
		
		/**
		  * Entity Constructor
		  * Public / Private Key generation
		 **/
		public Entity(){
			// INITIALIZATION

			// generate a public/private key
			try{
				// get an instance of KeyPairGenerator  for RSA	
				KeyPairGenerator keyPairG= KeyPairGenerator.getInstance("RSA");
				// Initialize the key pair generator for 1024 length
				keyPairG.initialize(1024);
				// Generate the key pair
				KeyPair keyP = keyPairG.generateKeyPair();
				
				// save the public/private key
				thePublicKey = keyP.getPublic();
				thePrivateKey = keyP.getPrivate();
				
			}catch(Exception e){
				System.out.println("Signature error");
				e.printStackTrace();
			}
		}

		/**
		  * Sign a message
		  * Parameters
		  * aMessage : byte[] to be signed
		  * Result : signature in byte[] 
		  **/
		public byte[] sign(byte[] aMessage){
			
			try{
				// use of java.security.Signature
				Signature signanture = Signature.getInstance("SHA1withRSA");
				// Init the signature with the private key
				signanture.initSign(thePrivateKey);

				// update the message
				signanture.update(aMessage);
				// sign
				return signanture.sign();
			}catch(Exception e){
				System.out.println("Signature error");
				e.printStackTrace();
				return null;
			}
			
		}
		
		/**
		  * Check aSignature is the signature of aMessage with aPK
		  * Parameters
		  * aMessage : byte[] to be signed
		  * aSignature : byte[] associated to the signature
		  * aPK : a public key used for the message signature
		  * Result : signature true or false
		  **/
		public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
			try{
				// use of java.security.Signature
				Signature signature = Signature.getInstance("SHA1withRSA");
				// init the signature verification with the public key
				signature.initVerify(aPK);

				// update the message
				signature.update(aMessage);
				// check the signature
				return signature.verify(aSignature);
			}catch(Exception e){
				System.out.println("Verify signature error");
				e.printStackTrace();
				return false;
			}
		}
		
		
		/**
		  * Sign a message
		  * Parameters
		  * aMessage : byte[] to be signed
		  * Result : signature in byte[] 
		  **/
		public byte[] mySign(byte[] aMessage){
			Cipher cipher;
			try{
				// get an instance of a cipher with RSA with ENCRYPT_MODE
				cipher = Cipher.getInstance("RSA");
				// Init the signature with the private key
				cipher.init(Cipher.ENCRYPT_MODE, this.thePrivateKey);
				// get an instance of the java.security.MessageDigest with SHA1
				MessageDigest sha1 = MessageDigest.getInstance("SHA1");
				// process the digest
				byte[] digest = sha1.digest(aMessage);
				// return the encrypted digest
				return cipher.doFinal(digest);
				
			}catch(Exception e){
				System.out.println("Signature error");
				e.printStackTrace();
				return null;
			}
			
		}
		
		/**
		  * Check aSignature is the signature of aMessage with aPK
		  * Parameters
		  * aMessage : byte[] to be signed
		  * aSignature : byte[] associated to the signature
		  * aPK : a public key used for the message signature
		  * Result : signature true or false
		  **/
		public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
			Cipher cipher;
			try{
				// get an instance of a cipher with RSA with DECRYPT_MODE
				cipher = Cipher.getInstance("RSA");
				
				// Init the signature with the public key
				cipher.init(Cipher.DECRYPT_MODE, aPK);
				// decrypt the signature
				byte[] derypt = cipher.doFinal(aSignature);
				// get an instance of the java.security.MessageDigest with SHA1
				MessageDigest sha1 = MessageDigest.getInstance("SHA1");
				// process the digest
				byte[] digest = sha1.digest(aMessage);
				
				// check if digest1 == digest2
				return Arrays.equals(aMessage , digest);

			}catch(Exception e){
				System.out.println("Verify signature error");
				e.printStackTrace();
				return false;
			}
		}	
		
		
		/**
		  * Encrypt aMessage with aPK
		  * Parameters
		  * aMessage : byte[] to be encrypted
		  * aPK : a public key used for the message encryption
		  * Result : byte[] ciphered message
		  **/
		public byte[] encrypt(byte[] aMessage, PublicKey aPK){
			try{
				// get an instance of RSA Cipher
				Cipher cipher = Cipher.getInstance("RSA");
				// init the Cipher in ENCRYPT_MODE and aPK
				cipher.init(Cipher.ENCRYPT_MODE, aPK);
				// use doFinal on the byte[] and return the ciphered byte[]
				return cipher.doFinal(aMessage);
				
			}catch(Exception e){
				System.out.println("Encryption error");
				e.printStackTrace();
				return null;
			}
		}

		/**
		  * Decrypt aMessage with the entity private key
		  * Parameters
		  * aMessage : byte[] to be encrypted
		  * Result : byte[] deciphered message
		  **/
		public byte[] decrypt(byte[] aMessage){
			try{
				// get an instance of RSA Cipher
				Cipher cipher = Cipher.getInstance("RSA");
				// init the Cipher in DECRYPT_MODE and aPK
				cipher.init(Cipher.DECRYPT_MODE, this.thePrivateKey);
				// use doFinal on the byte[] and return the deciphered byte[]
				
				return cipher.doFinal(aMessage);
				
			}catch(Exception e){
				System.out.println("DEcryption error");
				e.printStackTrace();
				return null;
			}

		}


}
