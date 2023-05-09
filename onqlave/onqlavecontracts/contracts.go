package onqlavecontracts

type EncryptionSecurityModel struct {
	Algorithm         string `json:"algo" validate:"required"`
	WrappingAlgorithm string `json:"wrapping_algo" validate:"required"`
}

type WrappingKey struct {
	EPK            string `json:"encrypted_private_key" validate:"required"`
	KeyFingerprint string `json:"key_fingerprint" validate:"required"`
}

type DataEncryptionKey struct {
	EDK string `json:"encrypted_data_key" validate:"required"`
	WDK string `json:"wrapped_data_key" validate:"required"`
}

type DataDecryptionKey struct {
	WDK string `json:"wrapped_data_key" validate:"required"`
}
