package big.pimpin.go2sleephoe;

import android.app.Application;
import android.os.Build;

import net.schmizz.sshj.common.SecurityUtils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class MainApplication extends Application {
    static File privateKeyFile;

    static {
        //System.setProperty("java.net.preferIPv6Addresses", "false");
        System.setProperty("java.net.preferIPv4Stack", "true");
        setupBouncyCastleForSshj();
    }

    // https://github.com/android-password-store/Android-Password-Store/blob/develop/app/src/main/java/app/passwordstore/util/git/sshj/SshjConfig.kt
    private static void setupBouncyCastleForSshj() {
        SecurityUtils.setRegisterBouncyCastle(false);
        SecurityUtils.setSecurityProvider(null);

        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; ++i) {
            if (!BouncyCastleProvider.PROVIDER_NAME.equals(providers[i].getName()))
                continue;

            providers = null;
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            try {
                Class.forName("sun.security.jca.Providers");
            } catch (final ClassNotFoundException ignored) {}
            Security.insertProviderAt(new BouncyCastleProvider(), i + 1);
            return;
        }

        Security.addProvider(new BouncyCastleProvider());
    }

    private static void generateAndWriteEd25519KeyPair(final File privateKeyFile, final File publicKeyFile) throws Throwable {
        byte[] publicKeyBytes = null;

        if (!privateKeyFile.exists()) {
            final AsymmetricCipherKeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            final AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

            final byte[] privateKeyBytes = OpenSSHPrivateKeyUtil.encodePrivateKey(keyPair.getPrivate());
            try (final FileWriter fileWriter = new FileWriter(privateKeyFile); final PemWriter pemWriter = new PemWriter(fileWriter)) {
                pemWriter.writeObject(new PemObject("OPENSSH PRIVATE KEY", privateKeyBytes));
            }

            publicKeyBytes = OpenSSHPublicKeyUtil.encodePublicKey(keyPair.getPublic());
        }

        if (publicKeyBytes != null || !publicKeyFile.exists()) {
            if (publicKeyBytes == null) {
                try (final FileReader fileReader = new FileReader(privateKeyFile); final PemReader pemReader = new PemReader(fileReader)) {
                    final Ed25519PrivateKeyParameters params = (Ed25519PrivateKeyParameters) OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(pemReader.readPemObject().getContent());
                    publicKeyBytes = OpenSSHPublicKeyUtil.encodePublicKey(params.generatePublicKey());
                }
            }

            try (final FileWriter fileWriter = new FileWriter(publicKeyFile)) {
                final String publicKeyString = String.format("ssh-ed25519 %s go2sleep@%s\n",
                        Base64.getEncoder().encodeToString(publicKeyBytes), Build.BOARD);
                fileWriter.write(publicKeyString);
            }
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();

        privateKeyFile = new File(getFilesDir(), "id_ed25519");
        final File publicKeyFile = new File(getExternalFilesDir(null), "id_ed25519.pub");

        try {
            generateAndWriteEd25519KeyPair(privateKeyFile, publicKeyFile);
        } catch (final Throwable th) {
            throw new RuntimeException(th);
        }
    }
}
