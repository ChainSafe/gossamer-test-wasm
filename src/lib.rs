pub use rstd;

extern {
    fn ext_print_num(data: i64);
    fn ext_print_utf8(offset: i32, len: i32);
    fn ext_print_hex(offset: i32, len: i32);
    fn ext_malloc(size: i32) -> i32;
    fn ext_free(addr: i32);
    fn ext_get_storage_into(key_data: i32, key_len: i32, value_data: i32, value_len: i32, value_offset: i32) -> i32;
    fn ext_set_storage(key_data: i32, key_len: i32, value_data: i32, value_len: i32);
    fn ext_storage_root(result_ptr: i32);
    fn ext_get_allocated_storage(key_data: i32, key_len: i32, written_out: i32) -> i32;
    fn ext_clear_storage(key_data: i32, key_len: i32);
    fn ext_clear_prefix(prefix_data: i32, prefix_len: i32);
    fn ext_blake2_256_enumerated_trie_root(values_data: i32, lens_data: i32, lens_len: i32, result: i32);
    fn ext_blake2_256(data: i32, length: i32, out: i32);
    fn ext_twox_128(data: i32, length: i32, out: i32);
    fn ext_ed25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32;
    fn ext_sr25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32;
}

#[no_mangle]
pub extern fn test_ext_print_num(data: i64) {
	unsafe {
		ext_print_num(data);
	}
}

#[no_mangle]
pub extern fn test_ext_print_utf8() {
	let message = rstd::alloc::format!("{}", "hello world!");
	unsafe {
		ext_print_utf8(message.as_ptr() as i32, message.len() as i32);
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
pub extern fn test_ext_ed25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32 {
   	unsafe {
   		ext_ed25519_verify(msg_data, msg_len, sig_data, pubkey_data)
   	}
}

#[no_mangle]
pub extern fn test_ext_twox_128(data: i32, length: i32, out: i32) {
   	unsafe {
   		ext_twox_128(data, length, out)
   	}
}

#[no_mangle]
pub extern fn test_ext_sr25519_verify(msg_data: i32, msg_len: i32, sig_data: i32, pubkey_data: i32) -> i32 {
   	unsafe {
   		ext_sr25519_verify(msg_data, msg_len, sig_data, pubkey_data)
   	}
}