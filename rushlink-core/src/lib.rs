use aes_gcm_siv::Nonce as AesNonce;
use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256GcmSiv,
};

use blake3::Hasher;
use rand_core::{OsRng, RngCore};
use rocksdb::DB;
use serde::{Deserialize, Serialize};

type Hash = [u8; 32];
type Nonce = [u8; 12];
type EncryptionKey = Hash;

#[derive(Debug)]
pub struct LinkStore {
    database: DB,
}

#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    EncryptionFailed,
    DecryptionFailed,
    SerializationFailed,
    DeserializationFailed,
    DatabaseReadFailed,
    DatabaseWriteFailed,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinkEntry {
    edit_password_hash: [u8; 32],
    encrypted_destination: Vec<u8>,
    nonce: [u8; 12],
    hit_counter: Option<u64>,
}

impl LinkStore {
    /// Open a Rocksdb dataset located at Path
    pub fn new(db_path: &str) -> Result<Self, String> {
        let db = DB::open_default(db_path);
        match db {
            Ok(d) => Ok(LinkStore { database: d }),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn add_url(
        &self,
        shortlink: &str,
        resolve_to: &str,
        password: &str,
        should_count_hits: bool,
    ) -> Result<(), Error> {
        let (hasher, key) = self.hash_and_verify_unique_shortlink(shortlink)?;

        let (encrypted_destination, nonce) = encrypt_destination(shortlink, resolve_to, hasher)?;

        let edit_password_hash = hash_password(password);

        let entry = LinkEntry {
            nonce: nonce,
            encrypted_destination,
            hit_counter: if should_count_hits { Some(0) } else { None },
            edit_password_hash,
        };

        self.write_to_db(&entry, &key)
    }

    pub fn resolve_url(&self, shortlink: &str) -> Result<Option<(String, Option<u64>)>, Error> {
        let mut hasher = Hasher::new();
        hasher.update(shortlink.as_bytes());
        let hash = hasher.finalize();
        let key: &Hash = hash.as_bytes();

        let query_result = self.database.get(key);
        match query_result {
            Err(_) => Err(Error::DatabaseReadFailed),
            Ok(None) => Ok(None),
            Ok(Some(v)) => self
                .resolve_from_entry(shortlink, key, hasher, v)
                .and_then(|(r, h)| Ok(Some((r, h)))),
        }
    }

    fn write_to_db(&self, entry: &LinkEntry, key: &Hash) -> Result<(), Error> {
        let encoding_result = serde_json::to_string(&entry);
        if encoding_result.is_err() {
            return Err(Error::SerializationFailed);
        }
        let encoded = encoding_result.unwrap();

        match self.database.put(key, encoded) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::DatabaseWriteFailed),
        }
    }

    fn resolve_from_entry(
        &self,
        shortlink: &str,
        key: &Hash,
        hasher: Hasher,
        serialized_entry: Vec<u8>,
    ) -> Result<(String, Option<u64>), Error> {
        let result: Result<LinkEntry, _> =
            serde_json::from_str(std::str::from_utf8(&serialized_entry).unwrap());
        if result.is_err() {
            return Err(Error::SerializationFailed);
        }
        let mut entry = result.unwrap();

        let resolved = decrypt_destination(
            shortlink,
            &entry.encrypted_destination,
            &entry.nonce,
            hasher,
        )?;

        if entry.hit_counter.is_some() {
            entry.hit_counter = entry.hit_counter.map(|count| count + 1);
            self.write_to_db(&entry, key)?;
        }
        Ok((resolved, entry.hit_counter))
    }

    fn hash_and_verify_unique_shortlink(&self, shortlink: &str) -> Result<(Hasher, Hash), Error> {
        let mut hasher = Hasher::new();

        hasher.update(shortlink.as_bytes());
        let key = hasher.finalize().as_bytes().clone();

        if self.database.get(key).is_err() {
            return Err(Error::AlreadyExists);
        }

        match self.database.get(key) {
            Err(_e) => Err(Error::DatabaseReadFailed),
            Ok(Some(_v)) => Err(Error::AlreadyExists),
            Ok(None) => Ok((hasher, key)),
        }
    }
}

fn hash_password(password: &str) -> Hash {
    blake3::hash(password.as_bytes()).as_bytes().clone()
}

fn encrypt_destination(
    shortlink: &str,
    resolve_to: &str,
    mut hasher: Hasher,
) -> Result<(Vec<u8>, Nonce), Error> {
    hasher.update(shortlink.as_bytes());
    let hash = hasher.finalize();
    let encryption_key: &EncryptionKey = hash.as_bytes();

    let mut nonce_buffer: Nonce = [0; 12]; //96 bits
    OsRng.fill_bytes(&mut nonce_buffer);
    let nonce = AesNonce::from_slice(&nonce_buffer);

    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(encryption_key));
    let encryption_result = cipher.encrypt(GenericArray::from_slice(nonce), resolve_to.as_bytes());

    match encryption_result {
        Ok(v) => Ok((v, nonce_buffer)),
        Err(_e) => Err(Error::EncryptionFailed),
    }
}

fn decrypt_destination(
    shortlink: &str,
    ciphertext: &Vec<u8>,
    nonce: &Nonce,
    mut hasher: Hasher,
) -> Result<String, Error> {
    hasher.update(shortlink.as_bytes());
    let hash = hasher.finalize();
    let encryption_key: &EncryptionKey = hash.as_bytes();

    let nonce = AesNonce::from_slice(nonce);

    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(encryption_key));

    let decryption_result = cipher.decrypt(AesNonce::from_slice(&nonce), ciphertext.as_ref());
    match decryption_result {
        Ok(v) => Ok(String::from_utf8(v).unwrap()),
        Err(_) => Err(Error::DecryptionFailed),
    }
}

#[cfg(test)]
mod tests {
    use crate::LinkStore;
    use tempfile::{tempdir, TempDir};

    const SHORTLINK: &str = "link-this";
    const DESTINATION_URL: &str = "https://example.com/destination";
    const PASSWORD: &str = "Password123";

    fn get_tmp_db() -> (TempDir, LinkStore) {
        let dir = tempdir().unwrap();
        let _file_path = dir.path().join("tempdb");
        let file_path = _file_path.to_str().unwrap();
        let store = LinkStore::new(file_path);
        assert!(store.is_ok());
        (dir, store.unwrap())
    }

    fn rm_temp_db(dir: TempDir) {
        dir.close().unwrap();
    }

    #[test]
    fn open_successful() {
        let (dir, _db) = get_tmp_db();
        rm_temp_db(dir);
    }

    #[test]
    fn open_fail_invalid_path() {
        let s = LinkStore::new("/this/path/does/not/exists/527/foo.db");
        assert!(s.is_err());
    }

    #[test]
    fn create_and_resolve_link() {
        let (dir, store) = get_tmp_db();

        let r = store.add_url(SHORTLINK, DESTINATION_URL, PASSWORD, true);
        assert!(r.is_ok());

        let q = store.resolve_url(SHORTLINK);
        assert!(q.is_ok());
        let queried = q.unwrap();
        assert!(queried.is_some());
        let (link, count) = queried.unwrap();
        assert_eq!(link, DESTINATION_URL);
        assert!(count.is_some());
        assert_eq!(count.unwrap(), 1);

        rm_temp_db(dir);
    }

    #[test]
    fn invalid_link() {
        let (dir, store) = get_tmp_db();

        let q = store.resolve_url("does-not-exist");
        assert!(q.is_ok());
        let queried = q.unwrap();
        assert!(queried.is_none());

        rm_temp_db(dir);
    }
}
