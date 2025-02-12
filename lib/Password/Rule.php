<?php
/**
 * Password_Rule
 *
 * Abstract class to implement a password matching rule
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password;

abstract class Rule {

	/**
	 * The password to validate
	 *
	 * @var string $password
	 * @access private
	 */
	protected ?string $password = null;

	/**
	 * Password Strength
	 *
	 * @access private
	 * @var int $password_strength
	 */
	private ?int $password_strength = null;

	/**
	 * Constructor
	 *
	 * @param int $password_strength
	 * @return void
	 */
	public function __construct(?int $password_strength) {
		$this->password_strength = $password_strength;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	abstract public function rule_matches(): bool;

	/**
	 * Get strength
	 *
	 * @access public
	 * @return int $strength
	 */
	public function get_strength(): int {
		if ($this->rule_matches()) {
			return $this->password_strength;
		}
		return Password_Strength::NONE;
	}

	/**
	 * Set password
	 *
	 * @access public
	 * @param string $password
	 */
	public function set_password($password): void {
		$this->password = $password;
	}

}
