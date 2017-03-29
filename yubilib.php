<?php

/**
 * Contains the yubilib library functions.
 *
 * @file
 * @copyright (c) 2016-2017 Tim Baumgard
 */

namespace yubilib;

/**
 * @defgroup constants Constants
 * This group contains all of the constants in the library.
 * @{
 */

const version = "1.0.0";
const serializationVersion = 1;
const cipherMethod = "aes-128-ecb";
const hmacMethod = "sha1";
const passcodeLength = 16;
const publicIdentityMinLength = 1;
const publicIdentityMaxLength = 16;
const privateIdentityOffset = 0;
const privateIdentityLength = 6;
const useCounterOffset = 6;
const useCounterLength = 2;
const timestampLowOffset = 8;
const timestampLowLength = 2;
const timestampHighOffset = 10;
const timestampHighLength = 1;
const sessionCounterOffset = 11;
const sessionCounterLength = 1;
const randomOffset = 12;
const randomLength = 2;
const crcOffset = 14;
const crcLength = 2;
const crcCheck = 0xf0b8;
const hexAlphabet = "0123456789abcdef";
const modhexAlphabet = "cbdefghijklnrtuv";
const passcodeHexLength = 32;
const publicIdentityMinHexLength = 2;
const publicIdentityMaxHexLength = 32;
const privateIdentityHexLength = 12;
const secretKeyHexLength = 32;

/** @} */

/**
 * @defgroup remote Remote validation
 * This group contains all functions used for remote validation.
 * @{
 */

/**
 * Validate a one-time password (OTP) against a v2.0 YubiCloud-style validation
 * server.
 *
 * @param $otp
 *   one-time password to validate as a modhex string
 * @param $settings
 *   array of settings to use, namely:
 *   - @c "clientId" (required) must be a integer string and a valid client ID
 *     for the server
 *   - @c "apiKey" (required) must be a base64-encoded string and valid API key
 *     for the server
 *   - @c "server" (optional) must be a string and a valid domain name, and it
 *     defaults to @c "api.yubico.com"
 *   - @c "timeout" (optional) must be a positive integer and is the maximum
 *     number of milliseconds the request is allowed to take, and it defaults to
 *     having no limit
 * @return
 *   @c true if the one-time password is valid and @c false otherwise
 * @throw requestTimeoutException
 * @throw badRequestException
 * @throw badResponseException
 * @see https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html
 */
function validateOneTimePasswordRemotely($otp, $settings) {
	$defaultSettings["clientId"] = "";
	$defaultSettings["apiKey"] = "";
	$defaultSettings["server"] = "api.yubico.com";
	$defaultSettings["timeout"] = 0;
	$settings += $defaultSettings;

	$nonce = namespace\encodeToHex(\random_bytes(20));
	$binaryApiKey = namespace\decodeFromBase64($settings["apiKey"]);

	// These pairs must be in alphabetical order for the signature to be valid.
	$query["id"] = $settings["clientId"];
	$query["nonce"] = $nonce;
	$query["otp"] = $otp;

	$data = \http_build_query($query);
	$key = $binaryApiKey;
	$requestSignature = \hash_hmac(namespace\hmacMethod, $data, $key, true);
	$query["h"] = namespace\encodeToBase64($requestSignature);

	$server = $settings["server"];
	$timeout = $settings["timeout"];
	$response = namespace\makeRemoteValidationRequest($server, $query, $timeout);

	if ($response === false) {
		throw new namespace\badRequestException(null);
	}

	$values = namespace\convertRemoteValidationResponseToArray($response);

	if ($values === false) {
		throw new namespace\badResponseException($response);
	}

	if (!isset($values["status"])) {
		throw new namespace\badResponseException($response);
	}

	$status = $values["status"];
	$badRequestStatuses[] = "BAD_OTP";
	$badRequestStatuses[] = "BAD_SIGNATURE";
	$badRequestStatuses[] = "MISSING_PARAMETER";
	$badRequestStatuses[] = "NO_SUCH_CLIENT";
	$badRequestStatuses[] = "OPERATION_NOT_ALLOWED";
	$badRequestStatuses[] = "REPLAYED_REQUEST";
	$badResponseStatuses[] = "BACKEND_ERROR";
	$badResponseStatuses[] = "NOT_ENOUGH_ANSWERS";

	if (\in_array($status, $badRequestStatuses)) {
		throw new namespace\badRequestException($response);
	}

	if (\in_array($status, $badResponseStatuses)) {
		throw new namespace\badResponseException($response);
	}

	foreach (["nonce", "otp", "h"] as $key) {
		if (!isset($values[$key])) {
			throw new namespace\badResponseException($response);
		}
	}

	try {
		$givenResponseSignature = namespace\decodeFromBase64($values["h"]);
	} catch (\RangeException $exception) {
		throw new namespace\badResponseException($response, $exception);
	}

	// The values must be in canonical form to get the signature to match.
	// They must be in alphabetical order and not contain the signature.
	\ksort($values, \SORT_STRING);
	unset($values["h"]);

	$data = namespace\reduceResponseValues($values);
	$key = $binaryApiKey;
	$responseSignature = \hash_hmac(namespace\hmacMethod, $data, $key, true);

	if (!\hash_equals($nonce, $values["nonce"])) {
		throw new namespace\badResponseException($response);
	}

	if (!\hash_equals($otp, $values["otp"])) {
		throw new namespace\badResponseException($response);
	}

	if (!\hash_equals($responseSignature, $givenResponseSignature)) {
		throw new namespace\badResponseException($response);
	}

	return $status == "OK";
}

/** @} */

/**
 * @defgroup local Local validation
 * This group contains all functions used for local validation.
 * @{
 */

/**
 * Validate a one-time password (OTP) locally against given credentials.
 *
 * @param $otp
 *   one-time password to validate as a string in modhex format
 * @param $credentials
 *   array of credentials, namely:
 *   - @c "publicIdentity" is the known public identity, which must be a string
 *     in modhex format
 *   - @c "privateIdentity" is the known public identity, which must be the
 *     result of hashing it using password_hash()
 *   - @c "secretKey" is the known secret key, which must be a binary string
 *   - @c "counter" is the known counter value, which must be a positive integer
 * @return
 *   array containing whether the one-time password is valid at index @c 0 and
 *   the counter value from the one-time password at index @c 1
 * @see https://developers.yubico.com/OTP/OTPs_Explained.html
 * @see https://www.yubico.com/wp-content/uploads/2015/03/YubiKeyManual_v3.4.pdf
 */
function validateOneTimePasswordLocally($otp, $credentials) {
	$state = 0b10;
	$counter = null;

	$publicIdentityHexLength = \strlen($otp) - namespace\passcodeHexLength;
	$publicIdentity = \substr($otp, 0, $publicIdentityHexLength);

	$otp = namespace\decodeFromHex(namespace\translateModhexToHex($otp));
	$publicIdentityLength = \strlen($otp) - namespace\passcodeLength;
	$passcode = \substr($otp, $publicIdentityLength);

	if (\hash_equals($credentials["publicIdentity"], $publicIdentity)) {
		$state |= 0b10;
	} else {
		$state |= 0b11;
	}

	$decryptedPasscode = namespace\decryptPasscode($passcode, $credentials["secretKey"]);

	$offset = namespace\privateIdentityOffset;
	$length = namespace\privateIdentityLength;
	$privateIdentity = \substr($decryptedPasscode, $offset, $length);

	$offset = namespace\useCounterOffset;
	$length = namespace\useCounterLength;
	$useCounter = \substr($decryptedPasscode, $offset, $length);

	$offset = namespace\sessionCounterOffset;
	$length = namespace\sessionCounterLength;
	$sessionCounter = \substr($decryptedPasscode, $offset, $length);

	$calculatedCrc = namespace\calculateCrc16($decryptedPasscode);
	$calculatedCrcString = \pack("S", $calculatedCrc);
	$checkCrcString = \pack("S", namespace\crcCheck);

	$useCounter = \unpack("v", $useCounter);
	$useCounter = $useCounter[1];

	$sessionCounter = \unpack("C", $sessionCounter);
	$sessionCounter = $sessionCounter[1];

	$counter = ($useCounter << 8) | $sessionCounter;

	if (\hash_equals($calculatedCrcString, $checkCrcString)) {
		$state |= 0b10;
	} else {
		$state |= 0b11;
	}

	if (\password_verify($privateIdentity, $credentials["privateIdentity"])) {
		$state |= 0b10;
	} else {
		$state |= 0b11;
	}

	if ($counter > $credentials["counter"]) {
		$state |= 0b10;
	} else {
		$state |= 0b11;
	}

	return [$state == 0b10, $counter];
}

/**
 * Prepare credentials for serialization or for use in locally validating a
 * one-time password (OTP) if the credentials haven't been stored in prepared
 * form. This decodes some of the credentials to binary strings and
 * cryptographically hashes the private identity.
 *
 * @param $credentials
 *   credentials to prepare
 * @return
 *   array of prepared credentials
 */
function prepareCredentials($credentials) {
	$credentials["privateIdentity"] = namespace\decodeFromHex($credentials["privateIdentity"]);
	$credentials["privateIdentity"] = \password_hash($credentials["privateIdentity"], \PASSWORD_DEFAULT);
	$credentials["secretKey"] = namespace\decodeFromHex($credentials["secretKey"]);

	return $credentials;
}

/**
 * Serialize prepared credentials to a string. Serialized credentials should be
 * stored in a secure, encrypted manner.
 *
 * @param $preparedCredentials
 *   prepared credentials to serialize
 * @return
 *   serialized credentials as a string
 * @see prepareCredentials()
 * @see deserializeCredentials()
 */
function serializeCredentials($preparedCredentials) {
	$version = namespace\serializationVersion;
	$publicIdentity = $preparedCredentials["publicIdentity"];
	$counter = $preparedCredentials["counter"];
	$secretKey = $preparedCredentials["secretKey"];
	$privateIdentity = $preparedCredentials["privateIdentity"];

	return \pack("CZ32a16Va*", $version, $publicIdentity, $secretKey, $counter, $privateIdentity);
}

/**
 * Deserialize serialized credentials.
 *
 * @param $serializedCredentials
 *   serialized credentials
 * @return
 *   array of credentials
 * @see serializeCredentials()
 */
function deserializeCredentials($serializedCredentials) {
	$formatString = "Cversion/Z32publicIdentity/a16secretKey/Vcounter/a*privateIdentity";
	$credentials = \unpack($formatString, $serializedCredentials);

	unset($credentials["version"]);

	return $credentials;
}

/** @} */

/**
 * @defgroup format Format validation
 * This group contains all functions used to validate credentials and the
 * various formats they can be in.
 * @{
 */

/**
 * Determine if a value is a public identity.
 *
 * @param $value
 *   value to check
 * @param $format
 *   expected format: @c "binary", @c "modhex", or @c "hex"
 * @return
 *   @c true if the value is a public identity and @c false otherwise
 */
function isPublicIdentity($value, $format) {
	if (!\is_string($value)) {
		return false;
	}

	$length = \strlen($value);

	if ($format != "binary") {
		$minimumLength = namespace\publicIdentityMinHexLength;
		$maximumLength = namespace\publicIdentityMaxHexLength;
	} else {
		$minimumLength = namespace\publicIdentityMinLength;
		$maximumLength = namespace\publicIdentityMaxLength;
	}

	if ($length < $minimumLength || $length > $maximumLength) {
		return false;
	}

	return namespace\isInFormat($value, $format);
}

/**
 * Determine if a value is a private identity.
 *
 * @param $value
 *   value to check
 * @param $format
 *   expected format: @c "binary", @c "modhex", or @c "hex"
 * @return
 *   @c true if the value is a private identity and @c false otherwise
 */
function isPrivateIdentity($value, $format) {
	if (!\is_string($value)) {
		return false;
	}

	if ($format != "binary") {
		$expectedLength = namespace\privateIdentityHexLength;
	} else {
		$expectedLength = namespace\privateIdentityLength;
	}

	if (\strlen($value) != $expectedLength) {
		return false;
	}

	return namespace\isInFormat($value, $format);
}

/**
 * Determine if a value is a secret key.
 *
 * @param $value
 *   value to check
 * @param $format
 *   expected format: @c "binary", @c "modhex", or @c "hex"
 * @return
 *   @c true if the value is a secret key and @c false otherwise
 */
function isSecretKey($value, $format) {
	if (!\is_string($value)) {
		return false;
	}

	if ($format != "binary") {
		$expectedLength = namespace\secretKeyHexLength;
	} else {
		$expectedLength = namespace\secretKeyLength;
	}

	if (\strlen($value) != $expectedLength) {
		return false;
	}

	return namespace\isInFormat($value, $format);
}

/**
 * Determine if a value is a one-time password (OTP).
 *
 * @param $value
 *   value to check
 * @param $format
 *   expected format: @c "binary", @c "modhex", or @c "hex"
 * @return
 *   @c true if the value is a one-time password and @c false otherwise
 */
function isOneTimePassword($value, $format) {
	if (!\is_string($value)) {
		return false;
	}

	$length = \strlen($value);

	if ($format != "binary") {
		$minimumLength = namespace\publicIdentityMinHexLength + namespace\passcodeHexLength;
		$maximumLength = namespace\publicIdentityMaxHexLength + namespace\passcodeHexLength;
	} else {
		$minimumLength = namespace\publicIdentityMinLength + namespace\passcodeLength;
		$maximumLength = namespace\publicIdentityMaxLength + namespace\passcodeLength;
	}

	if ($length < $minimumLength || $length > $maximumLength) {
		return false;
	}

	return namespace\isInFormat($value, $format);
}

/**
 * Determine if a value is a hex string.
 *
 * @param $value
 *   value to check
 * @return
 *   @c true if the value is a hex string and @c false otherwise
 */
function isHex($value) {
	return \is_string($value) && namespace\isInAlphabet($value, namespace\hexAlphabet);
}

/**
 * Determine if a value is a modhex string.
 *
 * @param $value
 *   value to check
 * @return
 *   @c true if the value is a modhex string and @c false otherwise
 */
function isModhex($value) {
	return \is_string($value) && namespace\isInAlphabet($value, namespace\modhexAlphabet);
}

/** @} */

/**
 * @defgroup support Supporting functions
 * This group contains all supporting functions that aren't too useful outside
 * of the library.
 * @{
 */

/**
 * Make a remote validation request.
 *
 * @param $serverDomainName
 *   server domain name
 * @param $queryVariables
 *   array of query variables
 * @param $timeout
 *   maximum number of milliseconds that the request can take as a positive
 *   integer or @c 0 for no limit
 * @return
 *   server response as a string if the request succeeds or @c false otherwise
 * @throw requestTimeoutException
 */
function makeRemoteValidationRequest($serverDomainName, $queryVariables, $timeout) {
	$query = \http_build_query($queryVariables);
	$url = "https://{$serverDomainName}/wsapi/2.0/verify?{$query}";

	$yubilibVersion = namespace\version;
	$phpVersion = \PHP_VERSION;
	$userAgent = "yubilib/{$yubilibVersion} PHP/{$phpVersion}";

	$curl = \curl_init();
	\curl_setopt($curl, \CURLOPT_URL, $url);
	\curl_setopt($curl, \CURLOPT_USERAGENT, $userAgent);
	\curl_setopt($curl, \CURLOPT_TIMEOUT_MS, $timeout);
	\curl_setopt($curl, \CURLOPT_PROTOCOLS, \CURLPROTO_HTTPS);
	\curl_setopt($curl, \CURLOPT_FAILONERROR, 1);
	\curl_setopt($curl, \CURLOPT_MAXREDIRS, 0);
	\curl_setopt($curl, \CURLOPT_RETURNTRANSFER, 1);

	$response = \curl_exec($curl);

	if (\curl_errno($curl) == \CURLE_OPERATION_TIMEDOUT) {
		throw new requestTimeoutException();
	}

	\curl_close($curl);

	return $response;
}

/**
 * Convert a remote validation response string to an array.
 *
 * @param $response
 *   response string
 * @return
 *   array of response values or @c false if parsing failed
 */
function convertRemoteValidationResponseToArray($response) {
	$variables = [];
	$lines = \preg_split("/[\\r\\n]+/", $response, -1, \PREG_SPLIT_NO_EMPTY);

	foreach ($lines as $line) {
		$pieces = \explode("=", $line, 2);

		if (\count($pieces) != 2) {
			return false;
		}

		$variables[$pieces[0]] = $pieces[1];
	}

	return $variables;
}

/**
 * Reduce the response values of a remote validation request to a HTTP-like
 * query string in the same manner that server encoded them.
 *
 * @param $values
 *   array of response values
 * @return
 *  response values reduced to a string
 */
function reduceResponseValues($values) {
	$reduction = "";

	foreach ($values as $key => $value) {
		$reduction .= "{$key}={$value}&";
	}

	$reduction = \rtrim($reduction, "&");

	return $reduction;
}

/**
 * Encrypt a one-time password passcode.
 *
 * @param $passcode
 *   passcode to encrypt
 * @param $secretKey
 *   secret key to use to encrypt the passcode
 * @return
 *   encrypted passcode
 */
function encryptPasscode($passcode, $secretKey) {
	$data = $passcode;
	$method = namespace\cipherMethod;
	$password = $secretKey;
	$options = \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING;

	return \openssl_encrypt($data, $method, $password, $options);
}

/**
 * Decrypt a one-time password passcode.
 *
 * @param $passcode
 *   passcode to decrypt
 * @param $secretKey
 *   secret key used to encrypt the passcode
 * @return
 *   decrypted passcode
 */
function decryptPasscode($passcode, $secretKey) {
	$data = $passcode;
	$method = namespace\cipherMethod;
	$password = $secretKey;
	$options = \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING;

	return \openssl_decrypt($data, $method, $password, $options);
}

/**
 * Calculate the CRC-16 for a binary string.
 *
 * @param $binaryString
 *   binary string of which to calculate the CRC
 * @return
 *   calculated CRC as an integer
 * @see https://www.yubico.com/wp-content/uploads/2015/03/YubiKeyManual_v3.4.pdf
 */
function calculateCrc16($binaryString) {
	$crc = 0xffff;
	$length = \strlen($binaryString);

	for ($i = 0; $i < $length; $i++) {
		$integer = \unpack("C", $binaryString{$i});
		$integer = $integer[1];

		$crc ^= $integer & 0xff;

		for ($j = 0; $j < 8; $j++) {
			$check = $crc & 1;

			$crc >>= 1;

			if ($check) {
				$crc ^= 0x8408;
			}
		}
	}

	return $crc;
}

/**
 * Translate standard hex into Yubico's modhex format.
 *
 * @param $hex
 *   hex string to translate
 * @return
 *   modhex string
 * @see translateModhexToHex()
 */
function translateHexToModhex($hex) {
	return \strtr($hex, namespace\hexAlphabet, namespace\modhexAlphabet);
}

/**
 * Translate Yubico's modhex format into standard hex.
 *
 * @param $modhex
 *   modhex string to translate
 * @return
 *   hex string
 * @see translateHexToModhex()
 */
function translateModhexToHex($modhex) {
	return \strtr($modhex, namespace\modhexAlphabet, namespace\hexAlphabet);
}

/**
 * Determine if a value is in a particular format.
 *
 * @param $value
 *   value to check
 * @param $format
 *   expected format: @c "binary", @c "modhex", or @c "hex"
 * @return
 *   @c true if the value is in the given format and @c false otherwise
 */
function isInFormat($value, $format) {
	if ($format == "modhex") {
		return namespace\isModHex($value);
	}

	if ($format == "hex") {
		return namespace\isHex($value);
	}

	return \is_string($value);
}

/**
 * Determine if a string only contains characters in a given alphabet.
 *
 * @param $string
 *   string to check
 * @param $alphabet
 *   string of characters that make up the alphabet
 * @return
 *  @c true if the string only contains characters in the given alphabet and
 *  @c false otherwise
 */
function isInAlphabet($string, $alphabet) {
	$escapedAlphabet = \preg_quote($alphabet, "/");
	$regex = "/^[{$escapedAlphabet}]+\$/";

	return \preg_match($regex, $string) == 1;
}

/**
 * Encode a binary string to a hex string in a timing-safe way.
 *
 * @param $binaryString
 *   binary string to encode
 * @return
 *   hex string
 * @see decodeFromHex()
 */
function encodeToHex($binaryString) {
	return \ParagonIE\ConstantTime\Encoding::hexEncode($binaryString);
}

/**
 * Decode a hex string to a binary string in a timing-safe way.
 *
 * @param $hexString
 *   hex string to decode
 * @return
 *   binary string
 * @see encodeToHex()
 */
function decodeFromHex($hexString) {
	return \ParagonIE\ConstantTime\Encoding::hexDecode($hexString);
}

/**
 * Encode a binary string to a base64 string in a timing-safe way.
 *
 * @param $binaryString
 *   binary string to encode
 * @return
 *   base64 string
 * @see decodeFromBase64()
 */
function encodeToBase64($binaryString) {
	return \ParagonIE\ConstantTime\Encoding::base64Encode($binaryString);
}

/**
 * Decode a base64 string to a binary string in a timing-safe way.
 *
 * @param $base64String
 *   base64 string to decode
 * @return
 *   binary string
 * @see encodeToBase64()
 */
function decodeFromBase64($base64String) {
	return \ParagonIE\ConstantTime\Encoding::base64Decode($base64String);
}

/** @} */
