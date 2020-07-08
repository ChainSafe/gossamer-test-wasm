use std::os::raw::{c_void};
use std::mem;
use std::ptr;

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
    fn ext_twox_256(data: i32, length: i32, out: i32);
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
    fn ext_get_child_storage_into(storage_key_data: i32, storage_key_len: i32, key_data: i32, key_len: i32, value_data: i32, value_len: i32, value_offset: i32) -> i32;
    fn ext_set_child_storage(storage_key_data: i32, storage_key_len: i32, key_data: i32, key_len: i32, value_data: i32, value_len: i32);
    fn ext_kill_child_storage(a: i32, b: i32);
    fn ext_sandbox_memory_new(a: i32, b: i32) -> i32;
    fn ext_sandbox_memory_teardown(a: i32);
    fn ext_sandbox_instantiate(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32;
    fn ext_sandbox_invoke(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32) -> i32;
    fn ext_sandbox_instance_teardown(a: i32);
    fn ext_get_allocated_child_storage(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32;
    fn ext_child_storage_root(a: i32, b: i32, c: i32) -> i32;
    fn ext_clear_child_storage(a: i32, b: i32, c: i32, d: i32);
    fn ext_secp256k1_ecdsa_recover_compressed(a: i32, b: i32, c: i32) -> i32;
    fn ext_sandbox_memory_get(a: i32, b: i32, c: i32, d: i32) -> i32;
    fn ext_sandbox_memory_set(a: i32, b: i32, c: i32, d: i32) -> i32;
    fn ext_log(a: i32, b: i32, c: i32, d: i32, e: i32);
}

fn alloc(size: usize) -> *mut c_void {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    return ptr as *mut c_void;
}

fn dealloc(ptr: *mut c_void, cap: usize) {
    unsafe {
        let _buf = Vec::from_raw_parts(ptr, 0, cap);
    }
}

#[no_mangle]
pub extern fn mock_execute_block() {
  unsafe {
    let key = [77u8; 16];
    let value = [0u8; 4];

    let key_ptr = alloc(key.len());
    ptr::copy(&key, key_ptr as *mut [u8; 16], key.len());
    let value_ptr = alloc(value.len());

    ext_set_storage(key_ptr as i32, key.len() as i32, value_ptr as i32, value.len() as i32);

    dealloc(key_ptr, key.len());
    dealloc(value_ptr, value.len());

    let data = String::from("System Number");
    let data_ptr = alloc(data.len());
    ptr::copy(&data, data_ptr as *mut String, data.len());

    let out = alloc(16);
    ext_twox_128(data_ptr as i32, data.len() as i32, out as i32);
    let hash = out as *mut [u8; 16];

    // let value: [u8; 4] = [1, 0, 0, 0];
    // let value_ptr = alloc(value.len());
    // ptr::copy(&value, value_ptr as *mut [u8; 4], value.len());

    // ext_set_storage(hash as i32, 16, value_ptr as i32, value.len() as i32);
    // dealloc(out, 16);
    // dealloc(value_ptr, value.len());
  }
}

#[no_mangle]
pub extern fn test_ext_log(a: i32, b: i32, c: i32, d: i32, e: i32) {
  unsafe {
    ext_log(a, b, c, d, e);
  }
}

#[no_mangle]
pub extern fn test_ext_kill_child_storage(a: i32, b: i32) {
  unsafe {
    ext_kill_child_storage(a, b);
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_memory_new(a: i32, b: i32) -> i32 {
  unsafe {
    ext_sandbox_memory_new(a, b)
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_memory_teardown(a: i32) {
  unsafe {
    ext_sandbox_memory_teardown(a);
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_instantiate(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
  unsafe {
    ext_sandbox_instantiate(a, b, c, d, e, f)
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_invoke(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32) -> i32 {
  unsafe {
    ext_sandbox_invoke(a, b, c, d, e, f, g, h)
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_instance_teardown(a: i32) {
  unsafe {
    ext_sandbox_instance_teardown(a);
  }
}

#[no_mangle]
pub extern fn test_ext_get_allocated_child_storage(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
  unsafe {
    ext_get_allocated_child_storage(a, b, c, d, e)
  }
}

#[no_mangle]
pub extern fn test_ext_child_storage_root(a: i32, b: i32, c: i32) -> i32 {
  unsafe {
    ext_child_storage_root(a, b, c)
  }
}

#[no_mangle]
pub extern fn test_ext_clear_child_storage(a: i32, b: i32, c: i32, d: i32) {
  unsafe {
    ext_clear_child_storage(a, b, c, d);
  }
}

#[no_mangle]
pub extern fn test_ext_secp256k1_ecdsa_recover_compressed(a: i32, b: i32, c: i32) -> i32 {
  unsafe {
    ext_secp256k1_ecdsa_recover_compressed(a, b, c)
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_memory_get(a: i32, b: i32, c: i32, d: i32) -> i32 {
  unsafe {
    ext_sandbox_memory_get(a, b, c, d)
  }
}

#[no_mangle]
pub extern fn test_ext_sandbox_memory_set(a: i32, b: i32, c: i32, d: i32) -> i32 {
  unsafe {
    ext_sandbox_memory_set(a, b, c, d)
  }
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
pub extern fn test_ext_twox_256(data: i32, length: i32, out: i32) {
    unsafe {
      ext_twox_256(data, length, out)
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

#[no_mangle]
pub extern fn test_ext_get_child_storage_into(storage_key_data: i32, storage_key_len: i32, key_data: i32, key_len: i32, value_data: i32, value_len: i32, value_offset: i32) -> i32 {
    unsafe {
      ext_get_child_storage_into(storage_key_data, storage_key_len, key_data, key_len, value_data, value_len, value_offset)
    }
}

#[no_mangle]
pub extern fn test_ext_set_child_storage(storage_key_data: i32, storage_key_len: i32, key_data: i32, key_len: i32, value_data: i32, value_len: i32) {
    unsafe {
      ext_set_child_storage(storage_key_data, storage_key_len, key_data, key_len, value_data, value_len)
    }
}
