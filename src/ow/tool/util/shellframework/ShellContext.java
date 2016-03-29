/*
 * Copyright 2006,2008 National Institute of Advanced Industrial Science
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

package ow.tool.util.shellframework;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ow.values.PrivaNetValue;

public class ShellContext<T> {
	//private short sizeOfRandomValue = 256;
	private ShellServer<T> shellServer;
	private Shell<T> shell;
	private T opaqueData;
	private PrintStream out;
	private List<Command<T>> commandList;
	private String command;
	private String[] args;
	private boolean interactive;
	private X509Certificate cert;
	private Set<byte[]> randomValues = new HashSet ();
	private PrivateKey privKey;

	public ShellContext(ShellServer<T> shellServer, Shell<T> shell, T opaqueData,
			PrintStream out,
			List<Command<T>> commandList, String command, String[] args, boolean interactive, PrivateKey privKey) {
		this.shellServer = shellServer;
		this.shell = shell;
		this.opaqueData = opaqueData;
		this.out = out;
		this.commandList = commandList;
		this.command = command;
		this.args = args;
		this.interactive = interactive;
		
		cert = PrivaNetValue.GenerateCertificate(PrivaNetValue.generateKeyPair ());
		
		/*
		for (short i = 0;i < sizeOfRandomValue;i++) {
			randomValue[i] = 0;
			
		}
		//*/
		this.privKey = privKey;
	}
	public ShellContext(ShellServer<T> shellServer, Shell<T> shell, T opaqueData,
			PrintStream out,
			List<Command<T>> commandList, String command, String[] args, boolean interactive, X509Certificate cert, PrivateKey privKey) {
		this.shellServer = shellServer;
		this.shell = shell;
		this.opaqueData = opaqueData;
		this.out = out;
		this.commandList = commandList;
		this.command = command;
		this.args = args;
		this.interactive = interactive;
		
		this.cert = cert;
		this.privKey = privKey;

		/*
		for (short i = 0;i < sizeOfRandomValue;i++) {
			randomValue[i] = 0;
			
		}
		//*/
	}

	public PrivateKey getPrivateKey () { return privKey; }
	public void addRandomValue (byte[] rd) { this.randomValues.add(rd); }
	public Set<byte[]> getRandomValue () { return randomValues; }
	public void clearRandomValue () { randomValues.clear(); }
	public X509Certificate getCertificate () { return this.cert; }
	public ShellServer<T> getShellServer() { return this.shellServer; }
	public Shell<T> getShell() { return this.shell; }
	public T getOpaqueData() { return this.opaqueData; }
	public PrintStream getOutputStream() { return this.out; }
	public List<Command<T>> getCommandList() { return this.commandList; }
	public String getCommand() { return this.command; }
	public void setArguments(String[] args) { this.args = args; }
	public String[] getArguments() { return this.args; }
	public boolean isInteractive() { return this.interactive; }
}
