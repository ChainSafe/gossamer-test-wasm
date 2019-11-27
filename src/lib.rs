extern {
    fn ext_print_num(data: i64);
    fn ext_print_utf8(offset: i32, size: i32);
    fn ext_print_hex(offset: i32, size: i32);
    fn ext_malloc(size: i32) -> i32;
    fn ext_free(addr: i32);
    fn ext_get_storage_into(key_data: i32, key_len: i32, value_data: i32, value_len: i32, value_offset: i32) -> i32;
    fn ext_set_storage(key_data: i32, key_len: i32, value_data: i32, value_len: i32);
    fn ext_storage_root(result_ptr: i32);
    fn ext_get_allocated_storage(key_data: i32, key_len: i32, written_out: i32) -> i32;
    fn ext_clear_storage(key_data: i32, key_len: i32);
    fn ext_clear_prefix(prefix_data: i32, prefix_len: i32);
    fn ext_blake2_256_enumerated_trie_root(values_data: i32, lens_data: i32, lens_len: i32, result: i32);
    fn ext_blake2_128(data: i32, length: i32, out: i32);
    fn ext_blake2_256(data: i32, length: i32, out: i32);
    fn ext_twox_64(data: i32, length: i32, out: i32);
    fn ext_twox_128(data: i32, length: i32, out: i32);
    fn ext_keccak_256(data: i32, length: i32, out: i32);
    fn ext_ed25519_generate(id_data: i32, seed: i32, seed_len: i32, out: i32);
    fn ext_ed25519_sign(id_data: i32, pubkey_data: i32, msg_data: i32, msg_len: i32, out: i32) -> i32;
    fn ext_ed25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32;
    fn ext_sr25519_generate(id_data: i32, seed: i32, seed_len: i32, out: i32);
    fn ext_sr25519_sign(id_data: i32, pubkey_data: i32, msg_data: i32, msg_len: i32, out: i32) -> i32;
    fn ext_sr25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32;
    fn ext_ed25519_public_keys(id_data: i32, result_len: i32) -> i32;
    fn ext_sr25519_public_keys(id_data: i32, result_len: i32) -> i32;
    fn ext_secp256k1_ecdsa_recover(msg_data: i32, sig_data: i32, pubkey_data: i32) -> i32;
    fn ext_is_validator() -> i32;
    fn ext_local_storage_set(kind: i32, key: i32, key_len: i32, value: i32, value_len: i32);
    fn ext_local_storage_get(kind: i32, key: i32, key_len: i32, value_len: i32) -> i32;
    fn ext_local_storage_compare_and_set(kind: i32, key: i32, key_len: i32, old_value: i32, old_value_len: i32, new_value: i32, new_value_len: i32) -> i32;
    fn ext_network_state(written_out: i32) -> i32;
    fn ext_submit_transaction(data: i32, len: i32) -> i32;
}

#[no_mangle]
pub extern fn test_ext_print_num(data: i64) {
	unsafe {
		ext_print_num(data);
	}
}

#[no_mangle]
pub extern fn test_ext_print_utf8(offset: i32, size: i32) {
	unsafe {
		ext_print_utf8(offset, size);
	}
}

#[no_mangle]
pub extern fn test_ext_print_hex(offset: i32, size: i32) {
	unsafe {
		ext_print_hex(offset, size);
	}
}

#[no_mangle]
pub extern fn test_ext_malloc(size: i32) -> i32 {
	unsafe {
		ext_malloc(size)
	}
}

#[no_mangle]
pub extern fn test_ext_free(addr: i32) {
	unsafe {
		ext_free(addr);
	}
}

#[no_mangle]
pub extern fn test_ext_get_storage_into(key_data: i32, key_len: i32, value_data: i32, value_len: i32, value_offset: i32) -> i32 {
   	unsafe {
   		ext_get_storage_into(key_data, key_len, value_data, value_len, value_offset)
   	}
}

#[no_mangle]
pub extern fn test_ext_set_storage(key_data: i32, key_len: i32, value_data: i32, value_len: i32) {
   	unsafe {
   		ext_set_storage(key_data, key_len, value_data, value_len)
   	}
}

#[no_mangle]
pub extern fn test_ext_storage_root(result_ptr: i32) {
   	unsafe {
   		ext_storage_root(result_ptr)
   	}
}

#[no_mangle]
pub extern fn test_ext_get_allocated_storage(key_data: i32, key_len: i32, written_out: i32) -> i32 {
   	unsafe {
   		ext_get_allocated_storage(key_data, key_len, written_out)
   	}
}

#[no_mangle]
pub extern fn test_ext_clear_storage(key_data: i32, key_len: i32) {
   	unsafe {
   		ext_clear_storage(key_data, key_len)
   	}
}

#[no_mangle]
pub extern fn test_ext_clear_prefix(prefix_data: i32, prefix_len: i32) {
   	unsafe {
   		ext_clear_prefix(prefix_data, prefix_len)
   	}
}

#[no_mangle]
pub extern fn test_ext_blake2_256_enumerated_trie_root(values_data: i32, lens_data: i32, lens_len: i32, result: i32) {
   	unsafe {
   		ext_blake2_256_enumerated_trie_root(values_data, lens_data, lens_len, result)
   	}
}

#[no_mangle]
pub extern fn test_ext_blake2_256(data: i32, length: i32, out: i32) {
   	unsafe {
   		ext_blake2_256(data, length, out)
   	}
} 

#[no_mangle]
pub extern fn test_ext_blake2_128(data: i32, length: i32, out: i32) {
    unsafe {
      ext_blake2_128(data, length, out)
    }
} 

#[no_mangle]
pub extern fn test_ext_ed25519_generate(id_data: i32, seed: i32, seed_len: i32, out: i32) {
    unsafe {
      ext_ed25519_generate(id_data, seed, seed_len, out)
    }
}

#[no_mangle]
pub extern fn test_ext_ed25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32 {
   	unsafe {
   		ext_ed25519_verify(msg_data, msg_len, sig_data, pubkey_data)
   	}
}

#[no_mangle]
pub extern fn test_ext_ed25519_sign(id_data: i32, pubkey_data: i32, msg_data: i32, msg_len: i32, out: i32) -> i32 {
    unsafe {
      ext_ed25519_sign(id_data, pubkey_data, msg_data, msg_len, out)
    }
}

#[no_mangle]
pub extern fn test_ext_ed25519_public_keys(id_data: i32, result_len: i32) -> i32 {
    unsafe {
      ext_ed25519_public_keys(id_data, result_len)
    }
}

#[no_mangle]
pub extern fn test_ext_twox_64(data: i32, length: i32, out: i32) {
    unsafe {
      ext_twox_64(data, length, out)
    }
}

#[no_mangle]
pub extern fn test_ext_twox_128(data: i32, length: i32, out: i32) {
   	unsafe {
   		ext_twox_128(data, length, out)
   	}
}

#[no_mangle]
pub extern fn test_ext_keccak_256(data: i32, length: i32, out: i32) {
    unsafe {
      ext_keccak_256(data, length, out)
    }
}

#[no_mangle]
pub extern fn test_ext_sr25519_generate(id_data: i32, seed: i32, seed_len: i32, out: i32) {
   	unsafe {
   		ext_sr25519_generate(id_data, seed, seed_len, out)
   	}
}

#[no_mangle]
pub extern fn test_ext_sr25519_sign(id_data: i32, pubkey_data: i32, msg_data: i32, msg_len: i32, out: i32) -> i32 {
    unsafe {
      ext_sr25519_sign(id_data, pubkey_data, msg_data, msg_len, out)
    }
}

#[no_mangle]
pub extern fn test_ext_sr25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32 {
    unsafe {
      ext_sr25519_verify(msg_data, msg_len, sig_data, pubkey_data)
    }
}

#[no_mangle]
pub extern fn test_ext_sr25519_public_keys(id_data: i32, result_len: i32) -> i32 {
    unsafe {
      ext_sr25519_public_keys(id_data, result_len)
    }
}

#[no_mangle]
pub extern fn test_ext_secp256k1_ecdsa_recover(msg_data: i32, sig_data: i32, pubkey_data: i32) -> i32 {
    unsafe {
      ext_secp256k1_ecdsa_recover(msg_data, sig_data, pubkey_data)
    }
}

#[no_mangle]
pub extern fn test_ext_is_validator() -> i32 {
    unsafe {
      ext_is_validator()
    }
}

#[no_mangle]
pub extern fn test_ext_local_storage_set(kind: i32, key: i32, key_len: i32, value: i32, value_len: i32) {
    unsafe {
      ext_local_storage_set(kind, key, key_len, value, value_len)
    }
}

#[no_mangle]
pub extern fn test_ext_local_storage_get(kind: i32, key: i32, key_len: i32, value_len: i32) -> i32 {
    unsafe {
      ext_local_storage_get(kind, key, key_len, value_len)
    }
}

#[no_mangle]
pub extern fn test_ext_local_storage_compare_and_set(kind: i32, key: i32, key_len: i32, old_value: i32, old_value_len: i32, new_value: i32, new_value_len: i32) -> i32 {
    unsafe {
      ext_local_storage_compare_and_set(kind, key, key_len, old_value, old_value_len, new_value, new_value_len)
    }
}

#[no_mangle]
pub extern fn test_ext_network_state(written_out: i32) -> i32 {
    unsafe {
      ext_network_state(written_out)
    }
}

#[no_mangle]
pub extern fn test_ext_submit_transaction(data: i32, len: i32) -> i32 {
    unsafe {
      ext_submit_transaction(data, len)
    }
}
