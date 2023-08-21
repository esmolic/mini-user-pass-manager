import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

public class Login {

	public static void main(String[] args) {
		Console sc = System.console();
		String user = args[0];
		String password = "";
		byte[] salt, hash;
		if (user == null || !Data.getData().containsKey(user)) {

			if (!Data.getData().containsKey(user)) {
				int timesWrong = -1;
				if (Data.getTriedNonexistentUsernames().containsKey(user))
					timesWrong = Data.getTriedNonexistentUsernames().get(user);

				timesWrong++;

				if (timesWrong > 5) {
					System.out.println("Blocking login attempts for username " + user);

					Data.triedNonexistent(user, -1);

					System.exit(0);
				}

				Data.triedNonexistent(user, timesWrong);

				try {
					TimeUnit.SECONDS.sleep(timesWrong);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}

			}

			System.out.print("Password: ");
			password = new String(sc.readPassword());
			System.out.println("Username or password incorrect");
			return;
		}
		int timesWrong = Integer.valueOf(new String(Data.getData().get(user)[3], StandardCharsets.UTF_8));
		if (timesWrong > 5) {
			System.out.println("Blocking login attempts for username " + user);
			UserManagement.removeUser(user);
			System.exit(0);
		}

		try {
			TimeUnit.SECONDS.sleep(timesWrong);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		salt = Data.getData().get(user)[0];
		hash = Data.getData().get(user)[1];

		// if forcepass flag set
		if (new String(Data.getData().get(user)[2], StandardCharsets.UTF_8).equals("1")) {

			System.out.print("Old password: ");
			password = new String(sc.readPassword());
			if (!checkHash(salt, hash, password)) {
				System.out.println("Password does not match the current one");
				UserManagement.setWrongCounter(user, ++timesWrong);
				System.exit(0);
			}
			UserManagement.updatePassword(user);
		} else {

			System.out.print("Password: ");

			password = new String(sc.readPassword());

			if (checkHash(salt, hash, password)) {
				UserManagement.setWrongCounter(user, 0);
				System.out.println("Login successful");
			} else {
				UserManagement.setWrongCounter(user, ++timesWrong);
				System.out.println("Username or password incorrect");
			}

		}

	}

	public static boolean checkHash(byte[] salt, byte[] hash, String password) {
		byte[] newHash = null;
		try {
			newHash = Data.getHash(password, salt);

		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}

		return new String(newHash, StandardCharsets.UTF_8).equals(new String(hash, StandardCharsets.UTF_8));

	}

}
