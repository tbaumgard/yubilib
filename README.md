# yubilib

`yubilib` is a PHP library for remotely and locally validating [YubiKey](https://www.yubico.com/products/yubikey-hardware/) one-time passwords (OTPs). It also includes a YubiKey emulator for testing and development as well as functions to check whether the various components of a one-time password are in the correct format.

## Documentation

HTML-formatted documentation can be generated using [Doxygen](http://www.stack.nl/~dimitri/doxygen/) and the included `Doxyfile` file. The generated documentation is placed in the `documentation/html` directory, and the main page can be found at `documentation/html/index.html`.

## Example Usage

### Remote Validation

Validating a one-time password using a validation server is fairly straightforward. First, either [get a client ID and API key](https://upgrade.yubico.com/getapikey/) to use [Yubico's YubiCloud](https://www.yubico.com/products/services-software/yubicloud/) validation servers or
[host a validation server yourself](https://developers.yubico.com/Software_Projects/Yubico_OTP/YubiCloud_Validation_Servers/).

Then, simply make a call to the server with those credentials:

```php
// Load the library and automatically load classes and dependencies as needed.
require_once "path/to/yubilib/vendor/autoload.php";

$otp = "kgucftudgcknghjjkunucgldkcvdtfhnbuikidrlnukt";
$settings["clientId"] = "12345";
$settings["apiKey"] = "IEFQSSBrZXkgaW4gYmFzZTY0IA==";
$settings["server"] = "api.yubico.com";
$settings["timeout"] = 10;

try {
	$isOtpValid = yubilib\validateOneTimePasswordRemotely($otp, $settings);
} catch (yubilib\requestTimeoutException $exception) {
	// Handle a request that timed out.
} catch (yubilib\badRequestException $exception) {
	// Handle a bad request, e.g., invalid server, client ID, or API key.
} catch (yubilib\badResponseException $exception) {
	// Handle a bad response, e.g., network or validation server issue.
}
```

### Local Validation

#### Storing Credentials

To be able to validate a one-time password, your application must first have credentials stored somewhere. `yubilib` includes functions to make this easier. For example:

```php
// Load the library and automatically load classes and dependencies as needed.
require_once "path/to/yubilib/vendor/autoload.php";

$userId = 12345;
$credentials["publicIdentity"] = "kgucftudgckn";
$credentials["privateIdentity"] = "4ae4e40efa8a";
$credentials["secretKey"] = "637f70b3846347d55ee49016a7da70a2";
$credentials["counter"] = 0;

// Prepare the credentials to get them into the format that
// yubilib\serializeCredentials() and yubilib\validateOneTimePasswordLocally()
// expect. This includes hashing the private identity as a security measure.
$preparedCredentials = yubilib\prepareCredentialsForSerialization($credentials);

// Serialize the credentials to a string for easy storage.
$serializedCredentials = yubilib\serializeCredentials($credentials);

// Store the serialized credentials somewhere safe.
example\storeOneTimePasswordCredentials($userId, $serializedCredentials);
```

**Security Notice**: it is _absolutely essential_ that the credentials are stored in a secure and encrypted manner. If you're unsure how to do that properly, use remote validation and the YubiCloud validation servers instead.

#### Validating a One-Time Password

Once the credentials have been stored securely, validating a one-time password is pretty straightforward:

```php
// Load the library and automatically load classes and dependencies as needed.
require_once "path/to/yubilib/vendor/autoload.php";

$userId = 12345;
$otp = "kgucftudgcknghjjkunucgldkcvdtfhnbuikidrlnukt";

// Retrieve the stored credentials in serialized format.
$serializedCredentials = example\retriveOneTimePasswordCredentials($userId);

// Deserialize and validate the one-time password.
$credentials = yubilib\deserializeCredentials($serializedCredentials);
list($isOtpValid, $newCounter) = yubilib\validateOneTimePasswordLocally($otp, $credentials);

if ($isOtpValid) {
	// Update the counter and serialize the updated credentials.
	$credentials["counter"] = $newCounter;
	$serializedCredentials = yubilib\serializeCredentials($credentials);

	// Save the updated credentials, namely the counter, to prevent replay attacks.
	example\storeOneTimePasswordCredentials($userId, $serializedCredentials);
} else {
	// Notify the user that the one-time password is invalid.
	example\printOneTimePasswordErrorMessage();
}
```

#### Format Validation

The library also includes functions to validate the format of one-time passwords and their various components. Here are some examples:

```php
// Load the library and automatically load classes and dependencies as needed.
require_once "path/to/yubilib/vendor/autoload.php";

$publicIdentity = "kgucftudgckn";
$privateIdentity = "4ae4e40efa8a";
$secretKey = "637f70b3846347d55ee49016a7da70a2";
$otp = "kgucftudgcknghjjkunucgldkcvdtfhnbuikidrlnukt";

if (yubilib\isPublicIdentity($publicIdentity, "modhex")) {
	// Notify the user that the public identity is invalid.
	example\printPublicIdentityErrorMessage();
}

if (yubilib\isPrivateIdentity($privateIdentity, "hex")) {
	// Notify the user that the private identity is invalid.
	example\printPrivateIdentityErrorMessage();
}

if (yubilib\isSecretKey($secretKey, "hex")) {
	// Notify the user that the secret key is invalid.
	example\printSecretKeyErrorMessage();
}

if (yubilib\isOneTimePassword($otp, "modhex")) {
	// Notify the user that the one-time password is invalid.
	example\printOneTimePasswordErrorMessage();
}
```

#### Emulator

The `emulator.php` file contains a YubiKey emulator for testing and development purposes. By default, this file doesn't do anything in order to prevent abuse if this file is made publicly available, e.g., on a website. You must first comment out the `return` statement at the beginning of the file to use the emulator.

Once that is done, you can modify the values in `emulator.php` and run it to generate and print a one-time password.

## Notes

- Your application should include some kind of recovery mechanism for users who lose their YubiKeys.
- Your application should mitigate brute-force and other attacks by only allowing a specific amount of login attempts during a specific time interval.
- With regards to local validation, it is _absolutely essential_ that the credentials are stored in a secure and encrypted manner. If you're unsure how to do that properly, use remote validation and the YubiCloud validation servers instead.
- In the interest of full disclosure, this library hasn't gone through a third-party security audit.
