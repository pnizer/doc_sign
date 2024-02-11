use js_sys::Uint8Array;
use secp256k1::SECP256K1;
use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

pub mod pdf_gen;

#[wasm_bindgen]
pub struct Sha256Digester {
    hasher: Sha256,
}

#[wasm_bindgen]
impl Sha256Digester {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Sha256Digester {
            hasher: Sha256::new(),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    pub fn finish(self) -> JsValue {
        let hash = self.hasher.finalize();
        let array = Uint8Array::from(&hash[..]);
        array.into()
    }
}

#[wasm_bindgen (js_name = addSignedPageToPdf)]
pub fn add_signed_page_to_pdf_wasm(bytes: &[u8]) -> Uint8Array {
    let output = pdf_gen::add_signed_page_to_pdf(bytes);
    Uint8Array::from(&output[..])
}

pub struct EcdsaSecp256k1 {
    secret_key: Option<SecretKey>,
    public_key: PublicKey,
}
impl EcdsaSecp256k1 {
    pub fn from_secret(secret_key_bytes: &[u8]) -> Self {
        let context = SECP256K1;
        let secret_key = SecretKey::from_slice(secret_key_bytes).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&context, &secret_key);
        EcdsaSecp256k1 {
            secret_key: Some(secret_key),
            public_key,
        }
    }
    pub fn from_public(public_key_bytes: &[u8]) -> Self {
        let public_key = PublicKey::from_slice(public_key_bytes).expect("33 or 65 bytes");
        EcdsaSecp256k1 {
            secret_key: None,
            public_key,
        }
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let context = SECP256K1;
        let message = Message::from_digest_slice(data).expect("32 bytes");
        let signature = context
            .sign_ecdsa(&message, self.secret_key.as_ref().unwrap())
            .serialize_compact();
        signature.to_vec()
    }
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> bool {
        let context = SECP256K1;
        let message = Message::from_digest_slice(data).expect("32 bytes");
        let signature = Signature::from_compact(signature).expect("64 bytes");
        context
            .verify_ecdsa(&message, &signature, &self.public_key)
            .is_ok()
    }
}

#[wasm_bindgen(js_name = EcdsaSecp256k1)]
pub struct WasmEcdaSecp256k1 {
    inner: EcdsaSecp256k1,
}
#[wasm_bindgen(js_class = EcdsaSecp256k1)]
impl WasmEcdaSecp256k1 {
    #[wasm_bindgen(js_name = fromSecret)]
    pub fn from_secret(secret_key_bytes: &[u8]) -> Self {
        WasmEcdaSecp256k1 {
            inner: EcdsaSecp256k1::from_secret(secret_key_bytes),
        }
    }
    #[wasm_bindgen(js_name = fromPublic)]
    pub fn from_public(public_key_bytes: &[u8]) -> Self {
        WasmEcdaSecp256k1 {
            inner: EcdsaSecp256k1::from_public(public_key_bytes),
        }
    }
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        let public_key = self.inner.public_key();
        Uint8Array::from(&public_key[..])
    }
    pub fn sign(&self, data: &[u8]) -> Uint8Array {
        let signature = self.inner.sign(data);
        Uint8Array::from(&signature[..])
    }
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> bool {
        self.inner.validate(signature, data)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ecdsa_from_secret_is_generating_public_key() {
        let secret_key_bytes = [
            0x0f, 0xce, 0xa9, 0x3f, 0xde, 0xa0, 0x73, 0x7c, 0x82, 0xfd, 0x6b, 0xbc, 0x23,
            0xf2, 0x6a, 0xd0, 0x8e, 0x55, 0x41, 0xd4, 0xde, 0xa5, 0xfe, 0xc9, 0x26, 0x98,
            0x85, 0x88, 0x7d, 0x49, 0x8c, 0x88,
        ];
        let ecdsa = EcdsaSecp256k1::from_secret(&secret_key_bytes);
        let public_key = ecdsa.public_key();        
        assert_eq!(
            public_key,
            vec![
                0x02, 0x51, 0xaa, 0x6b, 0xbb, 0xbb, 0xcc, 0x84, 0xda, 0xcb, 0x16, 0xee, 0x5e,
                0xa0, 0xe9, 0xc8, 0x1d, 0x4b, 0xd1, 0x11, 0x90, 0xa6, 0x7c, 0x65, 0xde, 0x66,
                0x50, 0x7a, 0xa7, 0x29, 0x00, 0xb2, 0x01]
                
        );
    }

    #[test]
    fn test_ecdsa_sing() {
        let secret_key_bytes = [
            0x0f, 0xce, 0xa9, 0x3f, 0xde, 0xa0, 0x73, 0x7c, 0x82, 0xfd, 0x6b, 0xbc, 0x23,
            0xf2, 0x6a, 0xd0, 0x8e, 0x55, 0x41, 0xd4, 0xde, 0xa5, 0xfe, 0xc9, 0x26, 0x98,
            0x85, 0x88, 0x7d, 0x49, 0x8c, 0x88,
        ];
        let ecdsa = EcdsaSecp256k1::from_secret(&secret_key_bytes);

        let hash = [
            0x6e, 0x62, 0x97, 0xa4, 0x28, 0x49, 0x4a, 0x79, 0x8b, 0x6d, 0x67, 0x55, 0xf0,
            0x74, 0xda, 0xc9, 0x95, 0x56, 0xf8, 0xf4, 0xc3, 0xce, 0x2d, 0x4b, 0xb5, 0xcc,
            0xcc, 0xdc, 0x5b, 0x5c, 0xbe, 0x65,
        ];
        let signature = ecdsa.sign(&hash);
        assert_eq!(
            signature,
            vec![0x38, 0xea, 0x55, 0xe1, 0x35, 0x00, 0x7b, 0xbb, 0x37, 0x10, 0x30, 0x55, 0xf5,
            0x14, 0xd1, 0x63, 0xa4, 0xca, 0x5c, 0x21, 0x98, 0xf1, 0x06, 0x81, 0xd6, 0x18, 0xb3,
            0xa2, 0x9f, 0x53, 0xc3, 0xdd, 0x54, 0x4b, 0xfc, 0x17, 0xee, 0x18, 0x81, 0xc4, 0x95,
            0x19, 0xbe, 0x71, 0x91, 0xcc, 0x53, 0x55, 0x52, 0x3c, 0x22, 0x7d, 0xc9, 0xa9, 0x10,
            0x04, 0xf3, 0xf8, 0xe8, 0x56, 0x10, 0x3f, 0xa7, 0x46]
        );                
    }

    #[test]
    fn test_ecdsa_verify_signature() {
        let public_key = [
            0x02, 0x51, 0xaa, 0x6b, 0xbb, 0xbb, 0xcc, 0x84, 0xda, 0xcb, 0x16, 0xee, 0x5e,
            0xa0, 0xe9, 0xc8, 0x1d, 0x4b, 0xd1, 0x11, 0x90, 0xa6, 0x7c, 0x65, 0xde, 0x66,
            0x50, 0x7a, 0xa7, 0x29, 0x00, 0xb2, 0x01,
        ];
        let ecdsa = EcdsaSecp256k1::from_public(&public_key);
        let hash = [
            0x6e, 0x62, 0x97, 0xa4, 0x28, 0x49, 0x4a, 0x79, 0x8b, 0x6d, 0x67, 0x55, 0xf0,
            0x74, 0xda, 0xc9, 0x95, 0x56, 0xf8, 0xf4, 0xc3, 0xce, 0x2d, 0x4b, 0xb5, 0xcc,
            0xcc, 0xdc, 0x5b, 0x5c, 0xbe, 0x65,
        ];
        let signature = [
            0x38, 0xea, 0x55, 0xe1, 0x35, 0x00, 0x7b, 0xbb, 0x37, 0x10, 0x30, 0x55, 0xf5,
            0x14, 0xd1, 0x63, 0xa4, 0xca, 0x5c, 0x21, 0x98, 0xf1, 0x06, 0x81, 0xd6, 0x18, 0xb3,
            0xa2, 0x9f, 0x53, 0xc3, 0xdd, 0x54, 0x4b, 0xfc, 0x17, 0xee, 0x18, 0x81, 0xc4, 0x95,
            0x19, 0xbe, 0x71, 0x91, 0xcc, 0x53, 0x55, 0x52, 0x3c, 0x22, 0x7d, 0xc9, 0xa9, 0x10,
            0x04, 0xf3, 0xf8, 0xe8, 0x56, 0x10, 0x3f, 0xa7, 0x46,
        ];
        assert!(ecdsa.validate(&signature, &hash));
    }
}