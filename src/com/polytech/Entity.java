package com.polytech;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;



public class Entity {
	
	//keys pair
	public PublicKey myPublicKey;
	public PrivateKey myPrivatecKey;
	
	public Entity(){
	//generation of public and private key

	try {
		KeyPairGenerator keyPairG= KeyPairGenerator.getInstance("RSA");
		keyPairG.initialize(1024);
		KeyPair keyP = keyPairG.generateKeyPair();
		
		//save the key pair
		myPublicKey = keyP.getPublic();
		myPrivatecKey = keyP.getPrivate();
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		System.out.println("Error Signature RSA");
		e.printStackTrace();
	}

	
	}
	
	
	

}
