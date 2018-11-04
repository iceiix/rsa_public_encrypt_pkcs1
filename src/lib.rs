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
    }
}


