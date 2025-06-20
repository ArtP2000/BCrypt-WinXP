
NTSTATUS key_symmetric_vector_reset_gnu(struct key* args);
NTSTATUS key_symmetric_set_auth_data_gnu(struct key_symmetric_set_auth_data_params* args);
NTSTATUS key_symmetric_encrypt_gnu(struct key_symmetric_encrypt_params* args);
NTSTATUS key_symmetric_decrypt_gnu(struct key_symmetric_decrypt_params* args);
NTSTATUS key_symmetric_get_tag_gnu(struct key_symmetric_get_tag_params* args);
NTSTATUS key_symmetric_destroy_gnu(struct key* args);
NTSTATUS key_asymmetric_generate_gnu(struct key* args);
NTSTATUS key_asymmetric_export_gnu(struct key_asymmetric_export_params* args);
NTSTATUS key_asymmetric_import_gnu(struct key_asymmetric_import_params* args);
NTSTATUS key_asymmetric_verify_gnu(struct key_asymmetric_verify_params* args);
NTSTATUS key_asymmetric_sign_gnu(struct key_asymmetric_sign_params* args);
NTSTATUS key_asymmetric_destroy_gnu(struct key* args);
NTSTATUS key_asymmetric_duplicate_gnu(struct key_asymmetric_duplicate_params* args);
NTSTATUS key_asymmetric_decrypt_gnu(struct key_asymmetric_decrypt_params* args);
NTSTATUS key_asymmetric_encrypt_gnu(struct key_asymmetric_encrypt_params* args);
NTSTATUS key_asymmetric_derive_key_gnu(struct key_asymmetric_derive_key_params* args);