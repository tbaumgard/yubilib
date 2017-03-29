<?php

/**
 * Contains a YubiKey emulator for testing and development.
 *
 * @file
 * @copyright (c) 2016-2017 Tim Baumgard
 */

/** @cond */

// By default, this file doesn't do anything in order to prevent abuse if this
// file is made publicly available, e.g., on a website. Comment out this line
// when testing in a development environment to get the emulator to work.
return;

// Change the values to any valid input. Increment one or both of the counters
// to generate a new one-time password based on the same credentials.
$publicIdentity = "kgucftudgckn";
$privateIdentity = "4ae4e40efa8a";
$secretKey = "637f70b3846347d55ee49016a7da70a2";
$useCounter = 0x0001;
$timestamp = 0x000001;
$sessionCounter = 0x01;
$random = 0x1234;

// -----------------------------------------------------------------------------
// There's no need to edit anything below this line.
// -----------------------------------------------------------------------------

require_once __DIR__ . "/vendor/autoload.php";

// Convert the necessary pieces to binary.
$privateIdentity = yubilib\decodeFromHex($privateIdentity);
$secretKey = yubilib\decodeFromHex($secretKey);
$useCounter = pack("v", $useCounter);
$timestamp = pack("v", ($timestamp >> 2)) . pack("C", ($timestamp & 0xff));
$sessionCounter = pack("C", $sessionCounter);
$random = pack("v", $random);

// Calculate the CRC-16 and create the passcode.
$partialPasscode = $privateIdentity . $useCounter . $timestamp . $sessionCounter . $random;
$crc = pack("v", ~yubilib\calculateCrc16($partialPasscode));
$passcode = $partialPasscode . $crc;

// Encrypt the passcode and encode it to modhex.
$encryptedPasscode = yubilib\encryptPasscode($passcode, $secretKey);
$encryptedPasscodeHex = yubilib\encodeToHex($encryptedPasscode);
$encryptedPasscodeHex = yubilib\translateHexToModhex($encryptedPasscodeHex);

echo "{$publicIdentity}{$encryptedPasscodeHex}\n";

/** @endcond */
