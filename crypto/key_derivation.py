from argon2.low_level import hash_secret_raw, Type

def derive_key(master_password: str, salt: bytes,
               time_cost: int = 4, memory_cost: int = 102400, parallelism: int = 4,
               hash_len: int = 32) -> bytes:
    if isinstance(master_password, str):
        master_password = master_password.encode('utf-8')
    return hash_secret_raw(
        secret=master_password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )
