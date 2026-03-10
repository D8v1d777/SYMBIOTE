import dataset
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class IntelManager:
    """Professional Intel Database & Encrypted Vault using Dataset/SQLite"""
    def __init__(self, db_path="intel/arsenal.db", secret_key="OMNI_SECRET_VAULT"):
        self.db = dataset.connect(f"sqlite:///{db_path}")
        self.secret_key = secret_key
        self._init_crypto()
        self._init_tables()

    def _init_crypto(self):
        salt = b'arsenal_salt_1337'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.secret_key.encode()))
        self.fernet = Fernet(key)

    def _init_tables(self):
        self.targets = self.db['targets']
        self.loot = self.db['loot']
        self.vault = self.db['vault']

    def add_target(self, address, metadata=None):
        self.targets.upsert({
            'address': address,
            'metadata': json.dumps(metadata or {}),
            'last_seen': dataset.util.now()
        }, ['address'])

    def store_loot(self, target, loot_type, data):
        self.loot.insert({
            'target': target,
            'type': loot_type,
            'data': data,
            'timestamp': dataset.util.now()
        })

    def vault_set(self, key, value):
        encrypted = self.fernet.encrypt(value.encode()).decode()
        self.vault.upsert({'key': key, 'value': encrypted}, ['key'])

    def vault_get(self, key):
        entry = self.vault.find_one(key=key)
        if entry:
            return self.fernet.decrypt(entry['value'].encode()).decode()
        return None
