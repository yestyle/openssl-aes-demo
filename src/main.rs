use openssl::symm::{decrypt, encrypt, Cipher};
use ring::{digest, hmac};

fn hexdump(bytes: &[u8]) {
    for (i, byte) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            print!("{i:03X}: ");
        }
        print!("{byte:02X} ");
        if i % 16 == 15 {
            println!();
        }
    }
    // End of data new-line if bytes.len() isn't aligned to 16
    if bytes.len() % 16 != 0 {
        println!();
    }
    println!();
}

fn evp(passphrase: &[u8], salt: Option<&[u8]>, dk_len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    let mut hash = Vec::new();

    loop {
        v.clear();
        v.extend_from_slice(&hash);
        v.extend_from_slice(passphrase);
        if let Some(salt) = salt {
            v.extend_from_slice(salt);
        }
        println!("Source of hash:");
        hexdump(&v);

        hash.extend_from_slice(&digest::digest(&digest::SHA256, &v).as_ref());
        println!("Hash:");
        hexdump(&hash);

        if hash.len() >= dk_len {
            break;
        }
    }

    hash.drain(dk_len..);
    hash
}

fn pbkdf2(passphrase: &[u8], salt: Option<&[u8]>, iterations: u32, dk_len: usize) -> Vec<u8> {
    let salt = if let Some(salt) = salt { salt } else { &[] };

    let prf = hmac::Key::new(hmac::HMAC_SHA256, passphrase);
    let mut output = vec![0u8; dk_len];
    let mut block_num = 1u32;

    let mut remaining = dk_len;
    let mut offset = 0;

    while remaining > 0 {
        let mut block = [0u8; 32];
        let mut u = vec![0u8; 32];

        // Salt || INT_32_BE(block_num)
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_num.to_be_bytes());

        // U1 = PRF(Password, Salt || INT_32_BE(block_num))
        hmac::sign(&prf, &salt_block).as_ref().clone_into(&mut u);
        block.clone_from_slice(&u);

        for _ in 1..iterations {
            // Uj = PRF(Password, U_{j-1})
            hmac::sign(&prf, &u).as_ref().clone_into(&mut u);
            for i in 0..block.len() {
                block[i] ^= u[i];
            }
        }

        println!("Block {block_num}:");
        hexdump(&block);

        let block_len = remaining.min(block.len());
        output[offset..offset + block_len].copy_from_slice(&block[..block_len]);

        offset += block_len;
        remaining -= block_len;
        block_num += 1;
    }

    output
}

fn wrap_ciphertext(ciphertext: Vec<u8>, salt: Option<&[u8]>) -> Vec<u8> {
    if let Some(salt) = salt {
        let mut v = Vec::from(b"Salted__");
        v.extend_from_slice(salt);
        v.extend_from_slice(&ciphertext);
        v
    } else {
        ciphertext
    }
}

fn parse_ciphertext(ciphertext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if ciphertext.starts_with(b"Salted__") {
        (Vec::from(&ciphertext[8..16]), Vec::from(&ciphertext[16..]))
    } else {
        (Vec::new(), Vec::from(ciphertext))
    }
}

pub fn encrypt_with_evp_kdf(plaintext: &[u8], passphrase: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    let derived_key = evp(passphrase, salt, 48);
    let (key, iv) = (&derived_key[..32], &derived_key[32..]);

    wrap_ciphertext(
        encrypt(Cipher::aes_256_cbc(), key, Some(iv), &plaintext).unwrap(),
        salt,
    )
}

pub fn encrypt_with_pbkdf2_kdf(
    plaintext: &[u8],
    passphrase: &[u8],
    salt: Option<&[u8]>,
    iterations: u32,
) -> Vec<u8> {
    let derived_key = pbkdf2(passphrase, salt, iterations, 48);
    let (key, iv) = (&derived_key[..32], &derived_key[32..]);

    wrap_ciphertext(
        encrypt(Cipher::aes_256_cbc(), key, Some(iv), &plaintext).unwrap(),
        salt,
    )
}

pub fn decrypt_with_evp_kdf(ciphertext: &[u8], passphrase: &[u8]) -> Vec<u8> {
    let (salt, cipher) = parse_ciphertext(ciphertext);
    let derived_key = evp(
        passphrase,
        if salt.is_empty() { None } else { Some(&salt) },
        48,
    );
    let (key, iv) = (&derived_key[..32], &derived_key[32..]);

    decrypt(Cipher::aes_256_cbc(), key, Some(iv), &cipher).unwrap()
}

pub fn decrypt_with_pbkdf2_kdf(ciphertext: &[u8], passphrase: &[u8], iterations: u32) -> Vec<u8> {
    let (salt, cipher) = parse_ciphertext(ciphertext);
    let derived_key = pbkdf2(
        passphrase,
        if salt.is_empty() { None } else { Some(&salt) },
        iterations,
        48,
    );
    let (key, iv) = (&derived_key[..32], &derived_key[32..]);

    decrypt(Cipher::aes_256_cbc(), key, Some(iv), &cipher).unwrap()
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

    const PLAINTEXT: &[u8] = b"Hello, world!";
    const PASSPHRASE: &[u8] = b"drjom(&)(&)MOJRD";

    #[test]
    fn test_openssl_pbkdf2_hmac() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 10000
        // salt=0526EC6BCCE0E971
        // key=9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55
        // iv =5E4E0250801A7C68FA185133729D7798

        let mut derived_key = vec![0; 48];
        pbkdf2_hmac(
            PASSPHRASE,
            &hex!("0526EC6BCCE0E971"),
            10000,
            MessageDigest::sha256(),
            &mut derived_key,
        )
        .unwrap();

        assert_eq!(
            &derived_key[..32],
            &hex!("9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("5E4E0250801A7C68FA185133729D7798")
        );
    }

    #[test]
    fn test_evp_kdf_nosalt() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt
        // key=53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2
        // iv =ED889267E14BA02167ED96E226153158
        let derived_key = evp(PASSPHRASE, None, 48);
        assert_eq!(
            hex!("53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2"),
            &derived_key[..32]
        );
        assert_eq!(hex!("ED889267E14BA02167ED96E226153158"), &derived_key[32..]);
    }

    #[test]
    fn test_evp_kdf_salt() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt
        // salt=DB42A96B2AA5CECE
        // key=CD10B0CBE8CFF451CDF082F00DA4A3E6351BFD5996D7EF0E4ACEBE13B1382BF7
        // iv =115776C3DFD6EFEDA0076617A35B3438
        let derived_key = evp(PASSPHRASE, Some(&hex!("DB42A96B2AA5CECE")), 48);
        assert_eq!(
            hex!("CD10B0CBE8CFF451CDF082F00DA4A3E6351BFD5996D7EF0E4ACEBE13B1382BF7"),
            &derived_key[..32]
        );
        assert_eq!(hex!("115776C3DFD6EFEDA0076617A35B3438"), &derived_key[32..]);
    }

    #[test]
    fn test_encrypt_with_evp_kdf_nosalt() {
        // evp + nosalt
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -p -nosalt -in plaintext.txt -out encrypted.bin
        // key=53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2
        // iv =ED889267E14BA02167ED96E226153158
        assert_eq!(
            hex!("23 b2 31 7e 87 74 3b 5a  4a d9 8d fe 05 92 23 c1"),
            encrypt_with_evp_kdf(PLAINTEXT, PASSPHRASE, None).as_slice()
        );
    }

    #[test]
    fn test_encrypt_with_evp_kdf_salt() {
        // evp + salt
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -p -salt -in plaintext.txt -out encrypted.bin
        // salt=BE2BE3CFF1842371
        // key=FAE325C5C303419DB314338B131AF1D762E065D84B904CD6806E2B36047AD5D6
        // iv =5A51A86D29454D05F8BC649794080678
        assert_eq!(
            // Salted__ be 2b e3 cf f1 84 23 71 + ciphertext
            hex!("53 61 6c 74 65 64 5f 5f  be 2b e3 cf f1 84 23 71  a3 04 e4 ba 89 d0 60 d5  4c cd f5 c5 6d 02 2e ee"),
            encrypt_with_evp_kdf(PLAINTEXT, PASSPHRASE, Some(&hex!("BE2BE3CFF1842371"))).as_slice()
        );
    }

    #[test]
    fn test_decrypt_with_evp_kdf_nosalt() {
        assert_eq!(
            PLAINTEXT,
            decrypt_with_evp_kdf(
                &hex!("23 b2 31 7e 87 74 3b 5a  4a d9 8d fe 05 92 23 c1"),
                PASSPHRASE,
            )
            .as_slice()
        );
    }

    #[test]
    fn test_decrypt_with_evp_kdf_salt() {
        assert_eq!(
            PLAINTEXT,
            // Salted__ be 2b e3 cf f1 84 23 71 + ciphertext
            decrypt_with_evp_kdf(&hex!("53 61 6c 74 65 64 5f 5f  be 2b e3 cf f1 84 23 71  a3 04 e4 ba 89 d0 60 d5  4c cd f5 c5 6d 02 2e ee"), PASSPHRASE).as_slice()
        );
    }

    #[test]
    fn test_pbkdf2_kdf_salt_iter_10000() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 10000
        // salt=0526EC6BCCE0E971
        // key=9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55
        // iv =5E4E0250801A7C68FA185133729D7798
        let derived_key = pbkdf2(PASSPHRASE, Some(&hex!("0526EC6BCCE0E971")), 10000, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("5E4E0250801A7C68FA185133729D7798")
        );
    }

    #[test]
    fn test_pbkdf2_kdf_salt_iter_1() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 1
        // salt=ED0B59AB61394DAF
        // key=7BE0978302CDEA9A5C2DADC931BCC2559C7FA7FC3E378EC9D6276066D8026CFC
        // iv =3862EB4C5400259794232D09277C279E
        let derived_key = pbkdf2(PASSPHRASE, Some(&hex!("ED0B59AB61394DAF")), 1, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("7BE0978302CDEA9A5C2DADC931BCC2559C7FA7FC3E378EC9D6276066D8026CFC")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("3862EB4C5400259794232D09277C279E")
        );
    }

    #[test]
    fn test_pbkdf2_kdf_nosalt_iter_10000() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt -pbkdf2
        // key=2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B
        // iv =3C03BCBBAE2BD72F44366159358F3843
        let derived_key = pbkdf2(PASSPHRASE, None, 10000, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("3C03BCBBAE2BD72F44366159358F3843")
        );
    }

    #[test]
    fn test_pbkdf2_kdf_nosalt_iter_1() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt -pbkdf2 -iter 1
        // key=B0BC445D2D47544327D147982B25B86BBDE6A745338D0B9D681DDD61E3AE523F
        // iv =6EAD332E24753C990A6031E3C9D12B3B
        let derived_key = pbkdf2(PASSPHRASE, None, 1, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("B0BC445D2D47544327D147982B25B86BBDE6A745338D0B9D681DDD61E3AE523F")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("6EAD332E24753C990A6031E3C9D12B3B")
        );
    }

    #[test]
    fn test_encrypt_with_pbkdf2_kdf_nosalt_iter_10000() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -p -nosalt -pbkdf2 -in plaintext.txt -out encrypted.bin
        // key=2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B
        // iv =3C03BCBBAE2BD72F44366159358F3843
        assert_eq!(
            hex!("39 9a 67 ff 6d 53 61 3b  e5 bd 01 13 1c 9c 2e e1"),
            encrypt_with_pbkdf2_kdf(PLAINTEXT, PASSPHRASE, None, 10000).as_slice()
        );
    }

    #[test]
    fn test_encrypt_with_pbkdf2_kdf_salt_iter_10000() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -p -salt -pbkdf2 -in plaintext.txt -out encrypted.bin
        // salt=D28A2CBDE2512412
        // key=D0B6D47237B047DD6871138844DB5C82FD5039B783070B06FFDB9B589B2FDD15
        // iv =3D4B0FE3C3ACEE0ABB1CB825A84B0422
        assert_eq!(
            // Salted__ d2 8a 2c bd e2 51 24 12 + ciphertext
            hex!("53 61 6c 74 65 64 5f 5f  d2 8a 2c bd e2 51 24 12  c9 fa 88 c8 b3 94 02 51  6c 1d 3a 10 10 b6 96 55"),
            encrypt_with_pbkdf2_kdf(
                PLAINTEXT,
                PASSPHRASE,
                Some(&hex!("D28A2CBDE2512412")),
                10000
            )
            .as_slice()
        );
    }

    #[test]
    fn test_decrypt_with_pbkdf2_kdf_nosalt_iter_10000() {
        assert_eq!(
            PLAINTEXT,
            decrypt_with_pbkdf2_kdf(
                &hex!("39 9a 67 ff 6d 53 61 3b  e5 bd 01 13 1c 9c 2e e1"),
                PASSPHRASE,
                10000
            )
            .as_slice()
        );
    }

    #[test]
    fn test_decrypt_with_pbkdf2_kdf_salt_iter_10000() {
        assert_eq!(
            PLAINTEXT,
            decrypt_with_pbkdf2_kdf(
                // Salted__ d2 8a 2c bd e2 51 24 12 + ciphertext
                &hex!("53 61 6c 74 65 64 5f 5f  d2 8a 2c bd e2 51 24 12  c9 fa 88 c8 b3 94 02 51  6c 1d 3a 10 10 b6 96 55"),
                PASSPHRASE,
                10000
            )
            .as_slice()
        );
    }
}
