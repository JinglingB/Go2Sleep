package big.pimpin.go2sleephoe;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;

import com.hierynomus.sshj.key.KeyAlgorithms;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

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
import java.util.Arrays;
import java.util.Base64;

class AndroidConfig2 extends DefaultConfig {
    @Override
    protected void initKeyAlgorithms() {
        setKeyAlgorithms(Arrays.asList(
            KeyAlgorithms.EdDSA25519(),
            KeyAlgorithms.SSHRSA(),
            KeyAlgorithms.SSHDSA()
        ));
    }
}

public class MainActivity extends Activity {
    private static final String HOSTNAME = "192.168.1.1";
    private static final int PORT = 22;
    private static final String USERNAME = "toor";
    private static final String COMMAND = "C:\\ProgramData\\scoop\\apps\\sysinternals\\current\\psshutdown64.exe -accepteula -nobanner -d -t 0 & exit";
    File privateKeyFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        privateKeyFile = new File(getFilesDir(), "id_ed25519");

        //Toast.makeText(this, "Wir suchen dich", Toast.LENGTH_LONG).show();

        setupBouncyCastleForSshj();
        generateAndWriteEd25519KeyPair();

        final Thread thread = new Thread(() -> {
            try (final SSHClient ssh = new SSHClient(new AndroidConfig2())) {
                ssh.setConnectTimeout(5000);
                ssh.setTimeout(5000);
                ssh.addHostKeyVerifier(new PromiscuousVerifier());
                ssh.connect(HOSTNAME, PORT);
                ssh.authPublickey(USERNAME, privateKeyFile.getAbsolutePath());
                try (final Session session = ssh.startSession()) {
                    session.exec(COMMAND);
                }
            } catch (final Throwable th) {
                throw new RuntimeException(th);
            }
        });
        thread.start();
        try {
            thread.join(10000);
        } catch (final Throwable ignored) {}

        finishAndRemoveTask();
        System.exit(0);
    }

    // https://github.com/android-password-store/Android-Password-Store/blob/develop/app/src/main/java/app/passwordstore/util/git/sshj/SshjConfig.kt
    private static void setupBouncyCastleForSshj() {
        int bcIndex = -1;
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; ++i) {
            if (BouncyCastleProvider.PROVIDER_NAME.equals(providers[i].getName())) {
                bcIndex = i;
                break;
            }
        }

        if (bcIndex != -1) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            try {
                Class.forName("sun.security.jca.Providers");
            } catch (final ClassNotFoundException ignored) {}
            Security.insertProviderAt(new BouncyCastleProvider(), bcIndex + 1);
        } else {
            Security.addProvider(new BouncyCastleProvider());
        }

        SecurityUtils.setRegisterBouncyCastle(false);
        SecurityUtils.setSecurityProvider(null);
    }

    private void generateAndWriteEd25519KeyPair() {
        try {
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

            final File publicKeyFile = new File(getExternalFilesDir(null), "id_ed25519.pub");
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
        } catch (final Throwable th) {
            throw new RuntimeException(th);
        }
    }
}
