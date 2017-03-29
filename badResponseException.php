<?php

/**
 * Contains the yubilib::badResponseException class definition.
 *
 * @file
 * @copyright (c) 2016-2017 Tim Baumgard
 */

namespace yubilib;

/**
 * @addtogroup exceptions
 * @{
 */

/**
 * Exception for a bad response from a remote validation server.
 */
class badResponseException extends namespace\exception {

	private $response;

	/**
	 * Construct a new exception for a bad response.
	 *
	 * @param $response
	 *   server response as a string or @c null if it's not available
	 * @param $previousException
	 *   previous exception for exception chaining
	 */
	public function __construct($response, $previousException=null) {
		$this->response = \is_string($response) ? $response : null;

		parent::__construct("", 0, $previousException);
	}

	/**
	 * Get the response.
	 *
	 * @return
	 *   response as a string or @c null if it wasn't available
	 */
	public function response() {
		return $this->response;
	}

}

/** @} */
