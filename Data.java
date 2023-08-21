import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Data {
	public static final byte[][] EMPTY_DATA = { new byte[16], new byte[32], "0".getBytes(), "0".getBytes() };
	private static HashMap<String, byte[][]> data = new HashMap<String, byte[][]>();
	private static HashMap<String, Integer> triedNonexistentUsernames = new HashMap<String, Integer>();

	public static HashMap<String, byte[][]> getData() {
		readDB();
		return data;
	}

	public static void addToData(String user, byte[][] details) {
		data.put(user, details);
	}

	private static void readDB() {
		InputStream in = null;
		try {
			File db = Paths.get("./db.txt").toFile();
			if (!db.exists())
				return;
			in = Files.newInputStream(Paths.get("./db.txt"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		Scanner sc = new Scanner(in);

		try {
			int b;
			while ((b = in.read()) > -1) {

				String user = "";

				// skip initial blank line
				if (b == '\n')
					continue;
				user += (char) b;
				while (b != '\n') {
					try {
						b = in.read();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					user += (char) b;

				}
				byte[] forceChange = new byte[1];
				byte[] timesWrong = new byte[1];
				byte[][] details;
				byte[] salt = new byte[16];
				byte[] hash = new byte[32];
				// read flag
				b = in.read(forceChange);
				b = in.read(timesWrong);
				// read newline
				b = in.read();
				try {
					in.read(salt);
					in.read(hash);

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				details = new byte[4][];
				details[0] = salt;
				details[1] = hash;
				details[2] = forceChange;
				details[3] = timesWrong;

				data.put(user.trim(), details);
				// read newline
				b = in.read();

			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void refreshDB(String user, String password) {
		// create blank db file
		File db = new File("./db.txt");

		if (db.exists())
			try {
				db.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}

		try {
			FileOutputStream os = new FileOutputStream(db);
			byte[] salt, hash;
			// for each user
			for (String u : data.keySet()) {
				// write user with newline
				u = "\n" + u + "\n";
				os.write(u.getBytes());
				os.write((data.get(u.trim()))[2]);
				os.write((data.get(u.trim()))[3]);
				os.write("\n".getBytes());
				u = u.trim();
				if (password == null || user == null || !u.equals(user)) {
					// if this is not the user whose password we're changing, just write existing
					// salt hash for them
					os.write(data.get(u)[0]);
					os.write(data.get(u)[1]);

					continue;
				}

				// generate 16-bit salt
				salt = getNewSalt();

				// write salt
				os.write(salt);
				// compute hash for salt + password
				hash = getHash(password, salt);

				// save to data
				byte[][] details = { salt, hash, "0".getBytes() };
				data.put(u, details);

				// write hash
				os.write(hash);
			}

			readDB();

			os.close();
		} catch (IOException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	public static byte[] getHash(String password, byte[] salt) throws InvalidKeySpecException {
		SecretKeyFactory skf = null;
		try {
			skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 256);
		return skf.generateSecret(spec).getEncoded();
	}

	public static byte[] getNewSalt() {
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);
		return salt;

	}

	public static HashMap<String, Integer> getTriedNonexistentUsernames() {
		readNonexistent();
		return triedNonexistentUsernames;
	}

	public static void triedNonexistent(String user, int timesWrong) {
		readNonexistent();
		if (timesWrong == -1) {
			triedNonexistentUsernames.remove(user);
			System.out.println("User " + user + " successfully removed");

		}
		
		else triedNonexistentUsernames.put(user, timesWrong);
		refreshNE();
	}

	private static void refreshNE() {
		// create blank db file
		File db = new File("./ne.txt");

		if (db.exists())
			try {
				db.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}

		try {
			FileOutputStream os = new FileOutputStream(db);
			// for each user
			for (String u : triedNonexistentUsernames.keySet()) {
				// write user with newline
				u = u + "\n";
				os.write(u.getBytes());
				os.write((triedNonexistentUsernames.get(u.trim())).toString().getBytes());
				os.write("\n".getBytes());
				u = u.trim();

			}

			readNonexistent();

			os.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static void readNonexistent() {
		InputStream in = null;
		try {
			File db = Paths.get("./ne.txt").toFile();
			if (!db.exists())
				return;
			in = Files.newInputStream(Paths.get("./ne.txt"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		Scanner sc = new Scanner(in);

		try {
			int b;
			while ((b = in.read()) > -1) {

				String user = "";

				user += (char) b;
				while (b != '\n') {
					try {
						b = in.read();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					user += (char) b;

				}
				byte[] timesWrong = new byte[1];

				b = in.read(timesWrong);
				// read newline
				b = in.read();

				triedNonexistentUsernames.put(user.trim(),
						Integer.valueOf(new String(timesWrong, StandardCharsets.UTF_8)));


			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
