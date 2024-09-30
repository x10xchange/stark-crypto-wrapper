use malachite::{strings::ToLowerHexString, Integer};
use pyo3::prelude::*;
use starknet_crypto::{
    get_public_key as fetch_public_key, pedersen_hash, sign, verify as verify_signature,
    FieldElement,
};

mod messages;

// Converts a hexadecimal string to a FieldElement
fn str_to_field_element(hex_str: &str) -> Result<FieldElement, String> {
    FieldElement::from_hex_be(hex_str).map_err(|e| {
        format!(
            "Failed to convert hex string {} to FieldElement: {}",
            hex_str, e
        )
    })
}

fn int_to_field_element(int: &Integer) -> Result<FieldElement, String> {
    str_to_field_element(&int.to_lower_hex_string())
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
            .and_then(|left| {
                str_to_field_element(&right_hex)
                    .map_err(|e| e.into())
                    .and_then(|right| Ok(pedersen_hash(&left, &right).to_string()))
            })
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_sign_message(
    py: Python,
    priv_key_hex: String,
    msg_hash_hex: String,
    k_hex: String,
) -> PyResult<(String, String)> {
    py.allow_threads(move || {
        str_to_field_element(&priv_key_hex)
            .and_then(|priv_key| {
                str_to_field_element(&msg_hash_hex).and_then(|msg_hash| {
                    str_to_field_element(&k_hex).and_then(|k| {
                        sign(&priv_key, &msg_hash, &k)
                            .map(|signature| (signature.r.to_string(), signature.s.to_string()))
                            .map_err(|e| format!("Signing operation failed: {}", e))
                    })
                })
            })
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    })
}

#[pyfunction]
fn rs_verify_signature(
    py: Python,
    public_key_hex: String,
    msg_hash_hex: String,
    r_hex: String,
    s_hex: String,
) -> PyResult<bool> {
    py.allow_threads(move || {
        str_to_field_element(&public_key_hex)
            .and_then(|public_key| {
                str_to_field_element(&msg_hash_hex).and_then(|msg_hash| {
                    str_to_field_element(&r_hex).and_then(|r| {
                        str_to_field_element(&s_hex).and_then(|s| {
                            Ok(verify_signature(&public_key, &msg_hash, &r, &s).unwrap())
                        })
                    })
                })
            })
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

#[cfg(test)]
mod tests {
    //all test values are generated from python-sdk starkware implementation
    use malachite::{num::conversion::traits::FromStringBase, Integer};
    use messages::{get_limit_order_msg, get_transfer_msg};

    use super::*;

    fn wrapped_pedersen(left: &Integer, right: &Integer) -> Integer {
        let hashed_value = pedersen_hash(
            &int_to_field_element(left).unwrap(),
            &int_to_field_element(right).unwrap(),
        );
        Integer::from_string_base(16, &hashed_value.to_lower_hex_string()).unwrap()
    }

    #[test]
    fn test_get_limit_order_msg_buy() {
        let amount_collateral = Integer::from_string_base(10, "2485778700").unwrap();
        let amount_fee = Integer::from_string_base(10, "1328036591").unwrap();
        let amount_synthetic = Integer::from_string_base(10, "1143395141").unwrap();
        let asset_id_collateral = Integer::from_string_base(16, "a1545ed8").unwrap();
        let asset_id_synthetic = Integer::from_string_base(16, "d78f244").unwrap();
        let expiration_timestamp = 1;
        let is_buying_synthetic = true;
        let nonce = 237283943;
        let position_id = 711957234;

        let result = get_limit_order_msg(
            &asset_id_synthetic,
            &asset_id_collateral,
            is_buying_synthetic,
            &asset_id_collateral,
            &amount_synthetic,
            &amount_collateral,
            &amount_fee,
            nonce,
            position_id,
            expiration_timestamp,
            wrapped_pedersen,
        );

        let expected_hash = Integer::from_string_base(
            16,
            "63375cebdc56aad66f9df01c375cbaf6552c237bdd4a22f9c8eeb0cb151f38d",
        )
        .unwrap();
        assert!(result == expected_hash);
    }

    #[test]
    fn test_get_limit_order_msg_sell() {
        let amount_collateral = Integer::from_string_base(10, "1779339390").unwrap();
        let amount_fee = Integer::from_string_base(10, "2423504933").unwrap();
        let amount_synthetic = Integer::from_string_base(10, "918775584").unwrap();
        let asset_id_collateral = Integer::from_string_base(16, "c50a1245").unwrap();
        let asset_id_synthetic = Integer::from_string_base(16, "f5fc50c3").unwrap();
        let expiration_timestamp = 1;
        let is_buying_synthetic = false;
        let nonce = 2908915741;
        let position_id = 1643977314;

        let result = get_limit_order_msg(
            &asset_id_synthetic,
            &asset_id_collateral,
            is_buying_synthetic,
            &asset_id_collateral,
            &amount_synthetic,
            &amount_collateral,
            &amount_fee,
            nonce,
            position_id,
            expiration_timestamp,
            wrapped_pedersen,
        );

        let expected_hash = Integer::from_string_base(
            16,
            "4bd1a1c31b8248c8368af2f0bc0cca455b1a003fa051f84af297cff2e2bc411",
        )
        .unwrap();

        assert!(result == expected_hash);
    }

    #[test]
    fn test_get_transfer_msg() {
        let amount = Integer::from_string_base(10, "1000000").unwrap();

        let asset_id = Integer::from_string_base(
            16,
            "35596841893e0d17079c27b2d72db1694f26a1932a7429144b439ba0807d29c",
        )
        .unwrap();

        let receiver_public_key = Integer::from_string_base(
            16,
            "4e8f8d6d2dde51fdfc1717582318a437f1d81de4657a93d74c33c9793d12be3",
        )
        .unwrap();

        let expiration_timestamp = 1712135815;
        let nonce = 1;
        let sender_position_id = 4;
        let receiver_position_id = 3;

        let result = get_transfer_msg(
            &asset_id,
            &receiver_public_key,
            sender_position_id,
            receiver_position_id,
            nonce,
            &amount,
            expiration_timestamp,
            wrapped_pedersen,
        );

        let expected_hash = Integer::from_string_base(
            16,
            "4f7f3014abc11ddcd5406932441b220640906921faaf566e728a6a75aa7ab06",
        )
        .unwrap();

        assert!(result == expected_hash);
    }
}
