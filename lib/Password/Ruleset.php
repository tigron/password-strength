<?php
/**
 * Password_Ruleset
 *
 * The ruleset combines a set of rules. When calculating the password strength
 * for a given ruleset, we search for the rule with the HIGHEST score inside
 * the ruleset.
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password;

class Ruleset {

	/**
	 * Rules
	 *
	 * @access private
	 * @var Password_Rule[] $password_rules
	 */
	private $password_rules = [];

	/**
	 * The password to verify
	 *
	 * @access private
	 * @var string $password
	 */
	private ?string $password = null;

	/**
	 * Add password_rule
	 *
	 * @access public
	 * @param Password_Rule $password_rule
	 */
	public function add_rule(\Password\Rule $rule): void {
		$this->password_rules[] = $rule;
	}

	/**
	 * Import rules
	 *
	 * @access public
	 * @param array $password_rules
	 */
	public function import_rules(array $password_rules = []): void {
		foreach ($password_rules as $password_rule) {
			$this->add_rule($password_rule);
		}
	}

	/**
	 * Set password
	 *
	 * @access public
	 * @param string $password
	 * @return void
	 */
	public function set_password(string $password): void {
		$this->password = $password;
	}

	/**
	 * Get strength
	 *
	 * @access public
	 * @return int $strength
	 */
	public function get_strength(): int {
		$strength = null;
		$rule = null;
		foreach ($this->password_rules as $password_rule) {
			if (!$password_rule->matches($this->password)) {
				continue;
			}
			$rule_strength = $password_rule->get_strength();

			if ($strength === null) {
				$strength = $rule_strength;
				$rule = $password_rule;
				continue;
			}

			if ($rule_strength < $strength) {
				$strength = $rule_strength;
				$rule = $password_rule;
			}
		}
		if ($strength === null) {
			return \Password\Strength::NONE;
		}

		return $strength;
	}
}
