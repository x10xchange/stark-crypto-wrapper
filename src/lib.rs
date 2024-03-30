use pyo3::prelude::*;
use starknet_crypto::{
    FieldElement,
    pedersen_hash,
    sign,
    verify as verify_signature,
    get_public_key as fetch_public_key,
};

// Converts a hexadecimal string to a FieldElement
fn str_to_field_element(hex_str: &str) -> Result<FieldElement, String> {
    FieldElement::from_hex_be(hex_str).map_err(|e| format!("Failed to convert hex string to FieldElement: {}", e))
}

#[pyfunction]
fn rs_get_public_key(py: Python, private_key_hex: String) -> PyResult<String> {
    py.allow_threads(move || {
        str_to_field_element(&private_key_hex)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
            .and_then(|private_key| Ok(fetch_public_key(&private_key).to_string()))
    })
}

#[pyfunction]
fn rs_compute_pedersen_hash(py: Python, left_hex: String, right_hex: String) -> PyResult<String> {
    py.allow_threads(move || {
        str_to_field_element(&left_hex)
            .and_then(|left| str_to_field_element(&right_hex)
                .map_err(|e| e.into())
                .and_then(|right| Ok(pedersen_hash(&left, &right).to_string()))
            )
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_sign_message(py: Python, priv_key_hex: String, msg_hash_hex: String, k_hex: String) -> PyResult<(String, String)> {
    py.allow_threads(move || {
        str_to_field_element(&priv_key_hex)
            .and_then(|priv_key| 
                str_to_field_element(&msg_hash_hex)
                .and_then(|msg_hash| 
                    str_to_field_element(&k_hex)
                    .and_then(|k| {
                        sign(&priv_key, &msg_hash, &k)
                            .map(|signature| (signature.r.to_string(), signature.s.to_string()))
                            .map_err(|e| 
                                format!("Signing operation failed: {}", e)
                            )
                    })
                )
            )
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_verify_signature(py: Python, public_key_hex: String, msg_hash_hex: String, r_hex: String, s_hex: String) -> PyResult<bool> {
    py.allow_threads(move || {
        str_to_field_element(&public_key_hex)
            .and_then(|public_key| 
                str_to_field_element(&msg_hash_hex)
                .and_then(|msg_hash| 
                    str_to_field_element(&r_hex)
                    .and_then(|r| 
                        str_to_field_element(&s_hex)
                        .and_then(|s| Ok(verify_signature(&public_key, &msg_hash, &r, &s).unwrap()))
                    )
                )
            )
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pymodule]
fn fast_stark_crypto(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rs_get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(rs_compute_pedersen_hash, m)?)?;
    m.add_function(wrap_pyfunction!(rs_sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(rs_verify_signature, m)?)?;
    Ok(())
}
