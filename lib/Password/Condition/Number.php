<?php
/**
 * Condition lowercase
 *
 * This rule checks if a password contains a number
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition;

class Number implements \Password\Condition {

	/**
	 * @var bool $has_lowercase
	 * @access private
	 */
	private bool $has_number = false;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_lowercase
	 */
	public function __construct($has_number) {
		$this->has_number = $has_number;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		$numbers = '1234567890';
		$has_number = false;

		foreach (str_split($numbers) as $character) {
			if (strpos($password, $character) !== false) {
				$has_number = true;
			}
		}

		if ($has_number === $this->has_number) {
			return true;
		}

		return false;
	}

}

