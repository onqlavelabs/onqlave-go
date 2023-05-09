package onqlavemessages

const (
	SDK string = "SDK"

	FETCHING_ENCRYPTION_KEY_OPERATION                    string = "[onqlave] SDK: %s - Fetching encryption key"
	FETCHING_ENCRYPTION_KEY_RESPONSE_UNMARSHALING_FAILED string = "[onqlave] SDK: %s - Faild unmarshaling encryption key response"
	FETCHED_ENCRYPTION_KEY_OPERATION                     string = "[onqlave] SDK: %s - Fetched encryption key: operation took %s"

	FETCHING_DECRYPTION_OPERATION                        string = "[onqlave] SDK: %s - Fetching decryption key"
	FETCHING_DECRYPTION_KEY_RESPONSE_UNMARSHALING_FAILED string = "[onqlave] SDK: %s - Failed unmarshaling decryption key response"
	FETCHED_DECRYPTION_OPERATION                         string = "[onqlave] SDK: %s - Fetched decryption key: operation took %s"

	KEY_INVALID_WRAPPING_ALGO        string = "[onqlave] SDK: %s - Invalid wrapping algorithm"
	KEY_INVALID_WRAPPING_OPERATION   string = "[onqlave] SDK: %s - Invalid wrapping operation"
	KEY_UNWRAPPING_KEY_FAILED        string = "[onqlave] SDK: %s - Faild unwrapping encrytion key"
	KEY_INVALID_ENCRYPTION_OPERATION string = "[onqlave] SDK: %s - Invalid encryption operation"
	KEY_INVALID_DECRYPTION_OPERATION string = "[onqlave] SDK: %s - Invalid encryption operation"

	ENCRYPTING_OPERATION        string = "[onqlave] SDK: %s - Encrypting plain data"
	ENCRYPTED_OPERATION         string = "[onqlave] SDK: %s - Encrypted plain data: operation took %s"
	ENCRYPTION_OPERATION_FAILED string = "[onqlave] SDK: %s - Faild encrypting plain data"

	DECRYPTING_OPERATION        string = "[onqlave] SDK: %s - Decrypting cipher data"
	DECRYPTED_OPERATION         string = "[onqlave] SDK: %s - Decrypted cipher data: operation took %s"
	DECRYPTION_OPERATION_FAILED string = "[onqlave] SDK: %s - Faild decrypting cipher data"

	CLIENT_ERROR_EXTRACTING_CONTENT    string = "[onqlave] SDK: %s - Failed extracting request content"
	CLIENT_ERROR_CALCULATING_DIGEST    string = "[onqlave] SDK: %s - Failed calculating request digest"
	CLIENT_ERROR_CALCULATING_SIGNATURE string = "[onqlave] SDK: %s - Failed calculating request signature"
	CLIENT_ERROR_PORTING_REQUEST       string = "[onqlave] SDK: %s - Failed sending %s request"

	CLIENT_OPERATION_STARTED string = "[onqlave] SDK: %s - Sending request started"
	CLIENT_OPERATION_SUCCESS string = "[onqlave] SDK: %s - Sending request finished successfully: operation took %s"

	HTTP_OPERATION_STARTED string = "[onqlave] SDK: %s - Http operation started"
	HTTP_OPERATION_SUCCESS string = "[onqlave] SDK: %s - Http operation finished successfully: operation took %s"
)
