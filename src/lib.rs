extern crate num;
extern crate simple_asn1;
extern crate rand;

use num::bigint::{BigInt};
use simple_asn1::{from_der, ASN1Block};
use rand::Rng;

fn find_bitstrings(asns: Vec<ASN1Block>, mut result: &mut Vec<Vec<u8>>) {
    for asn in asns.iter() {
        match asn {
            ASN1Block::BitString(_, _, _, bytes) => result.push(bytes.to_vec()),
            ASN1Block::Sequence(_, _,  blocks) => find_bitstrings(blocks.to_vec(), &mut result),
            _ => (),
        }
    }
}

pub fn encrypt(der_pubkey: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    // Outer ASN.1 encodes 1.2.840.113549.1.1 OID and wraps a bitstring, find it
    let asns: Vec<ASN1Block> = from_der(&der_pubkey).map_err(|err| err.to_string())?;
    let mut result: Vec<Vec<u8>> = vec![];
    find_bitstrings(asns, &mut result);
    if result.len() == 0 {
        return Err("ASN.1 BitString not found in DER encoding of public key".to_string());
    }

    let inner_asn: Vec<ASN1Block> = from_der(&result[0]).map_err(|err| err.to_string())?;
    let (n, e) =
    match &inner_asn[0] {
        ASN1Block::Sequence(_, _, blocks) => {
            if blocks.len() != 2 {
                return Err("ASN.1 sequence bad length, expected exactly two blocks in inner Sequence".to_string());
            }

            let n = match &blocks[0] {
                ASN1Block::Integer(_, _, n) => n,
                _ => return Err("ASN.1 Integer modulus not found".to_string()),
            };

            let e = match &blocks[1] {
                ASN1Block::Integer(_, _, e) => e,
                _ => return Err("ASN.1 Integer exponent not found".to_string()),
            };
            (n, e)

        },
        _ => return Err("ASN.1 Sequence not found".to_string()),
    };

    // PKCS#1 padding https://tools.ietf.org/html/rfc8017#section-7.2.1 RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)
    let k = n.bits() / 8; // bytes in modulus
    // TODO: is it possible this will be a non-integral value, do we need to handle this case?
    //if k != 1024/8 { panic!("expected 1024-bit modulus"); }

    /* Steps:
     *
     *  1.  Length checking: If mLen > k - 11, output "message too long"
     *     and stop.
     */
    if message.len() > k - 11 {
        return Err("PKCS#1 error: message too long".to_string());
    }

    /*
     * 2.  EME-PKCS1-v1_5 encoding:
     *
     *     a.  Generate an octet string PS of length k - mLen - 3
     *         consisting of pseudo-randomly generated nonzero octets.
     *         The length of PS will be at least eight octets.
     */
    let mut padding = vec![1; k - message.len() - 3];
    let mut i = 0;
    while i < padding.len() {
        padding[i] = rand::thread_rng().gen_range(1, 255);
        i += 1;
    }

    /* b.  Concatenate PS, the message M, and other padding to form
     *     an encoded message EM of length k octets as
     *
     *            EM = 0x00 || 0x02 || PS || 0x00 || M.
     */
    let mut encoded_m = vec![0x00, 0x02];
    encoded_m.append(&mut padding.to_vec());
    encoded_m.append(&mut vec![0x00]);
    encoded_m.extend_from_slice(&message);

    /* 3.  RSA encryption:
     *
     *     a.  Convert the encoded message EM to an integer message
     *         representative m (see Section 4.2):
     *
     *           m = OS2IP (EM).
     */
    // OS2IP https://tools.ietf.org/html/rfc8017#section-4.2
    let m = BigInt::from_bytes_be(num::bigint::Sign::Plus, &encoded_m);

    /*     b.  Apply the RSAEP encryption primitive (Section 5.1.1) to
     *         the RSA public key (n, e) and the message representative m
     *         to produce an integer ciphertext representative c:
     *
     *            c = RSAEP ((n, e), m).
     */
    // https://tools.ietf.org/html/rfc8017#section-5.1.1
    /* 1.  If the message representative m is not between 0 and n - 1,
     *     output "message representative out of range" and stop.
     */
    if m.sign() != num::bigint::Sign::Plus || m > n - 1 {
        return Err("RSA error: message representative out of range".to_string());
    }

    // 2.  Let c = m^e mod n.
    let ciphertext_bigint = m.modpow(&e, &n);

    /*     c.  Convert the ciphertext representative c to a ciphertext C
     *         of length k octets (see Section 4.1):
     *
     *            C = I2OSP (c, k).
     */
    // 4.1. I2OSP https://tools.ietf.org/html/rfc8017#section-4.1
    let (_sign, ciphertext) = ciphertext_bigint.to_bytes_be();

    return Ok(ciphertext);
}


#[cfg(test)]
mod tests {
    use crate::encrypt;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
        assert_eq!(encrypt(&[], &[]), Err("Encountered an empty buffer decoding ASN1 block.".to_string()));
        //assert_eq!(encrypt(&[1], &[]), Err("Encountered an empty buffer decoding ASN1 block.".to_string())); // simple_asn1 panics TODO
        // TODO: test more errors

        /*
     $ openssl asn1parse -inform DER -in /tmp/d
    0:d=0  hl=3 l= 159 cons: SEQUENCE
    3:d=1  hl=2 l=  13 cons: SEQUENCE
    5:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   16:d=2  hl=2 l=   0 prim: NULL
   18:d=1  hl=3 l= 141 prim: BIT STRING
   */
        // 1024-bit (128-byte) public key, encoded in ASN.1 DER
        let pk = [48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129, 137, 2, 129, 129, 0, 149, 92, 126, 71, 214, 186, 100, 139, 40, 104, 65, 254, 200, 105, 71, 66, 241, 84, 172, 206, 206, 217, 49, 214, 16, 50, 6, 234, 97, 21, 170, 139, 234, 88, 220, 105, 27, 115, 56, 103, 53, 234, 84, 255, 129, 147, 41, 146, 68, 39, 120, 208, 141, 142, 39, 242, 182, 97, 4, 204, 236, 190, 104, 101, 234, 46, 71, 248, 55, 88, 213, 56, 145, 154, 142, 184, 144, 55, 105, 241, 179, 205, 174, 107, 40, 77, 46, 201, 197, 51, 20, 246, 95, 207, 227, 5, 210, 42, 107, 135, 219, 126, 207, 216, 181, 2, 130, 57, 203, 239, 232, 68, 220, 131, 211, 86, 168, 125, 193, 91, 148, 153, 109, 76, 109, 50, 2, 139, 2, 3, 1, 0, 1];

        // Raw RSA PKCS#1 encryption requires message isn't much longer than the key size (no hash)
        assert_eq!(encrypt(&pk, &[0; 128]), Err("PKCS#1 error: message too long".to_string()));
        assert_eq!(encrypt(&pk, &[0; 128-1]), Err("PKCS#1 error: message too long".to_string()));
        assert_eq!(encrypt(&pk, &[0; 128-2]), Err("PKCS#1 error: message too long".to_string()));
        assert_eq!(encrypt(&pk, &[0; 128-10]), Err("PKCS#1 error: message too long".to_string()));

        // Successful encryption
        // TODO: fix random bytes and add result test vectors
        assert_eq!(encrypt(&pk, &[]).is_ok(), true);
        assert_eq!(encrypt(&pk, &[1, 2, 3, 4]).is_ok(), true);
        assert_eq!(encrypt(&pk, &[0; 128-11]).is_ok(), true);
    }
}


