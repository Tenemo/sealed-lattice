use super::*;

#[test]
fn top_k_order_polynomial_masks_unselected_ranks() {
    let context = EvaluatorContext::new("top-k-order-value", 4).expect("context");
    let rank_values = [0_u64, 1, 2, 3, 4];
    let encrypted_ranks = context
        .key()
        .encrypt_slots(&rank_values, "rank-order")
        .expect("rank ciphertext");
    let order_values =
        top_k_order_value(&context, &encrypted_ranks, rank_values.len(), 2).expect("order");
    let decrypted = context
        .key()
        .decrypt_to_slots(&order_values)
        .expect("decrypt order");

    assert_eq!(&decrypted[..rank_values.len()], &[1, 2, 0, 0, 0]);
}
