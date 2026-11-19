use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString, c_char, c_void};

unsafe extern "C" {
    fn skyward_policy_allow(
        input: *const c_void,
        input_len: usize,
        source: *const c_char,
        target: *const c_char,
        class: *const c_char,
        permission: *const c_char,
        output: *mut *mut c_void,
        output_len: *mut usize,
    ) -> *const c_char;
}

/// Add an allow rule between two concrete types to a compiled policy.
pub fn allow(
    policy: &[u8],
    source: &str,
    target: &str,
    class: &str,
    permission: &str,
) -> Result<Vec<u8>> {
    let names = [source, target, class, permission]
        .map(CString::new)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("policy rule contains a NUL")?;
    let mut output = std::ptr::null_mut();
    let mut output_len = 0;
    // Input pointers stay valid through the call. Errors point to static strings.
    let error = unsafe {
        skyward_policy_allow(
            policy.as_ptr().cast(),
            policy.len(),
            names[0].as_ptr(),
            names[1].as_ptr(),
            names[2].as_ptr(),
            names[3].as_ptr(),
            &mut output,
            &mut output_len,
        )
    };
    if !error.is_null() {
        let error = unsafe { CStr::from_ptr(error) }.to_string_lossy();
        bail!("add allow {source} {target}:{class} {permission}: {error}");
    }
    // libsepol returns a malloc buffer. Copy it before freeing it.
    let bytes = unsafe {
        let bytes = std::slice::from_raw_parts(output.cast::<u8>(), output_len).to_vec();
        libc::free(output);
        bytes
    };
    Ok(bytes)
}
