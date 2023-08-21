import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class UserManagement {

	public static void main(String[] args) {
		parseCommand(args);
	}

	public static void parseCommand(String[] args) {
		switch (args[0]) {
		case "add":
			addUser(args[1]);
			break;
		case "passwd":
			updatePassword(args[1]);
			break;
		case "forcepass":
			forcePasswordChange(args[1]);
			break;
		case "del":
			removeUser(args[1]);
			break;
		default:
			throw new IllegalArgumentException("Unsupported command");
		}

	}

	private static void addUser(String user) {
		assertUserDoesntExist(user);
		Data.getData().put(user, Data.EMPTY_DATA);
		if (updatePassword(user)) {
			System.out.println("User " + user + " successfully added.");

			return;
		}

		System.out.println("User add failed. Password mismatch.");
		return;
	}

	private static void assertUserDoesntExist(String user) {
		if (Data.getData().keySet().contains(user)) {
			System.out.println("Username already exists.");
			System.exit(0);
		}

	}

	public static boolean updatePassword(String user) {
		assertUserExists(user);
		System.out.println(
				"Password should have at least 8 characters, one digit, one lowercase and one uppercase letter. No whitespace allowed.");
		Console sc = System.console();
		String password = "";

		System.out.print("Password:");
		password = new String(sc.readPassword());

		if (Data.getData().keySet().contains(user)) {
			byte[][] details = Data.getData().get(user);
			if (Login.checkHash(details[0], details[1], password)) {
				System.out.println("New password cannot be equal to the current one");
				return false;
			}
		}

		System.out.print("Repeat password:");
		if (password.equals(new String(sc.readPassword()))) {
			setPassword(user, password);
			System.out.println("Password successfully set.");
			UserManagement.setForcepassFlag(user, false);

			return true;
		}
		System.out.println("Password mismatch.");
		return false;
	}

	private static void assertUserExists(String user) {
		if (!Data.getData().keySet().contains(user)) {
			System.out.println("Username not found.");
			System.exit(0);
		}

	}

	public static void forcePasswordChange(String user) {
		assertUserExists(user);
		// set force change flag to true
		byte[][] details = Data.getData().get(user);
		details[2] = "1".getBytes();
		details[3] = "0".getBytes();
		Data.getData().put(user, details);
		Data.refreshDB(user, null);

		System.out.println("Forced password change for user " + user);

	}

	public static void removeUser(String user) {
		assertUserExists(user);
		Data.getData().remove(user);
		Data.refreshDB(null, null);
		System.out.println("User " + user + " successfully removed");
	}

	private static void setPassword(String user, String password) {
		assertUserExists(user);
		if (checkPasswordStrength(password))
			Data.refreshDB(user, password);
		else {
			System.out.println("Password set fail. Password not strong enough.");
			System.exit(0);
		}

	}

	private static boolean checkPasswordStrength(String password) {
		if (password.contains(" "))
			return false;
		if (password.contains("\t"))
			return false;
		if (password.length() < 8)
			return false;
		if (password.equals(password.toLowerCase()))
			return false;
		if (password.equals(password.toUpperCase()))
			return false;
		if (!password.matches(".*\\d+.*"))
			return false;

		return true;
	}

	public static void setWrongCounter(String user, Integer n) {
		byte[][] details = Data.getData().get(user);
		details[3] = n.toString().getBytes();
		Data.getData().put(user, details);
		Data.refreshDB(user, null);
	}
	
	public static void setForcepassFlag(String user, boolean flag) {
		byte[][] details = Data.getData().get(user);
		String flagString = flag? "1" : "0";
		details[2] = flagString.getBytes();
		Data.getData().put(user, details);
		Data.refreshDB(user, null);
	}

}
