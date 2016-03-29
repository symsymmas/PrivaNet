/*
 * Copyright 2006-2009 National Institute of Advanced Industrial Science
 * and Technology (AIST), and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ow.tool.dhtshell.commands;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import ow.dht.ByteArray;
import ow.dht.DHT;
import ow.dht.ValueInfo;
import ow.id.ID;
import ow.tool.util.shellframework.Command;
import ow.tool.util.shellframework.CommandUtil;
import ow.tool.util.shellframework.Shell;
import ow.tool.util.shellframework.ShellContext;
import ow.values.KeyMessage;
import ow.values.PrivaNetValue;

public final class GetCommand implements Command<DHT<String>> {
	private final static String[] NAMES = {"get"};

	public String[] getNames() { return NAMES; }

	public String getHelp() {
		return "get [-status] <key> [<key> ...]";
	}

	public byte[] decrypt (byte[] data, PrivateKey privKey) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			
			cipher.init(Cipher.DECRYPT_MODE, privKey); //privKey stored earlier
			
			return cipher.doFinal(data);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return data;
			
		}
		
	}
	/**
	 * Execute the command get. 
	 */
	public boolean execute(ShellContext<DHT<String>> context, X509Certificate cert) {
		DHT<String> dht = context.getOpaqueData();
		PrintStream out = context.getOutputStream();
		String[] args = context.getArguments();
		boolean showStatus = false;
		int argIndex = 0;

		if (argIndex < args.length && args[argIndex].startsWith("-")) {   // If there's almost one argument and the first one begins with "-", the the user want to see the status.
			showStatus = true;
			argIndex++;
		}

		if (argIndex >= args.length) {   // If it last on or 0 arguments, then show the usage.
			out.print("usage: " + getHelp() + Shell.CRLF);
			out.flush();

			return false;
		}

		Queue<ID> requestQueue = new ConcurrentLinkedQueue<ID>();   // Set a queue of IDs.

		// parse the command line and queue get requests
		List<String> keyList = new ArrayList<String>();

		for (; argIndex < args.length; argIndex++) {   // For each arguments:
			ID key = ID.parseID(args[argIndex], dht.getRoutingAlgorithmConfiguration().getIDSizeInByte());   // Set the key associated to.
			keyList.add(args[argIndex]);   // Add the key to the list.

			requestQueue.offer(key);   // Insert the actual key in the queue.
			
		}

		// process get requests
		ID[] keys = new ID[requestQueue.size()];
		for (int i = 0; i < keys.length; i++)
			keys[i] = requestQueue.poll();   // Take the next key.

		Set<ValueInfo<String>>[] values;
		values = dht.get(keys, context);
		
		for (int i = 0;i < keys.length;i++) {
			ID key = keys[i];
			
			System.out.println ("\n########## Back to the transmitter. ##########");
			//System.out.println ("key: " + key);
			if (values[i] != null) {
				if (!values[i].isEmpty ()) {
					for (ValueInfo<String> v: values[i]) {
						String challengeEncoded = v.getValue ();
						try {
							byte[] challengeCiphered = Base64.decode(challengeEncoded);
							byte[] challenge = decrypt (challengeCiphered, context.getPrivateKey ());
										
							System.out.println ("########## Flag decrypted. ##########");
							System.out.print ("Value of the flag after decryption:\n\t");
						    for(int j=0; j < challenge.length; j++) {
						        System.out.print(challenge[j] + " ");
						        
						    }
						    System.out.println ();
						    
						    context.addRandomValue((byte[]) challenge);
						    
						} catch (Base64DecodingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			}
		}
		
		// Second transmission.
		System.out.println ();
		System.out.println ("########## Back to the DHT. ##########");
		values = dht.get(keys, context);
		context.clearRandomValue();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < keys.length; i++) {
			ID key = keys[i];

			sb.append("key:   ").append(key).append(Shell.CRLF);

			if (values[i] != null) {
				if (!values[i].isEmpty()) {
					for (ValueInfo<String> v: values[i]) {
						String value = v.getValue(), msg = null;
						KeyMessage km = null;
						PrivaNetValue pnv = null;
						
						System.out.println ();
						System.out.println ("########## Back to the transmitter. ##########");
						
						System.out.print ("Decoding the message…  ");
						km = KeyMessage.getFromBase64(value);
						System.out.println ("  [OK]");
						
						try {
							msg = new String (km.getMsg(context.getPrivateKey()), "UTF-8");
						} catch (UnsupportedEncodingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							msg = new String (km.getMsg(context.getPrivateKey ()));
							
						}

						System.out.println ("Formating the value…  ");
						pnv = PrivaNetValue.getFromBase64(msg);
						
						System.out.println ();
						sb.append("value: ").append(pnv.getValue()).append(" ").append(v.getTTL() / 1000);

						ByteArray secret = v.getHashedSecret();
						if (secret != null) {
							sb.append(" ").append(secret);
						}

						sb.append(Shell.CRLF);
					}
				} else {
					sb.append("value:").append(Shell.CRLF);
					
				}
				
			} else {
				sb.append("routing failed: ").append(keyList.get(i)).append(Shell.CRLF);
				
			}
			
		}

		if (showStatus) {
			sb.append(CommandUtil.buildStatusMessage(context.getOpaqueData(), -1));
		}

		out.print(sb);
		out.flush();

		return false;
	}
	/**
	 * Used for implementation dependenci,es.
	 */
	@Override
	public boolean execute(ShellContext<DHT<String>> context) throws Exception {
		// TODO Auto-generated method stub
		return execute(context, null);
		
	}
	
}
