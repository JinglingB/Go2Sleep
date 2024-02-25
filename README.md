A no-configuration Android program to connect to your computer via SSH and put it to sleep.

1. Edit MainActivity.java to fix the IP, port, username etc.

2. Build and install on your Android device

3. Run the program. It won't work.

4. Read /sdcard/Android/data/big.pimpin.go2sleephoe/files/id_ed25519.pub and copy the line with the public key to your authorized_keys / administrators_authorized_keys

5. Run the program again. It should work.
