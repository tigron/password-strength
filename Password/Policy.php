<?php
/**
 * Password_Policy
 *
 * The ruleset combines multiple rulesets. When calculating the password strength
 * for a given policy, we search for the rule with the LOWEST score inside
 * the policy.
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
	 * @var Password_Ruleset[] $password_rulesets
	 */
	private $password_rulesets = [];

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
	public function add_password_ruleset(Password_Ruleset $password_ruleset): void {
		$this->password_rulesets[] = $password_ruleset;
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
		$lowest_strength = Password_Strength::NONE;
		foreach ($this->password_rulesets as $password_ruleset) {
			$password_ruleset->set_password($this->password);
			$ruleset_strength = $password_ruleset->get_strength();
			if (
				$lowest_strength === Password_Strength::NONE
				&& $ruleset_strength !== Password_Strength::NONE
			) {
				$lowest_strength = $ruleset_strength;
				continue;
			}

			if ($rule_strength < $lowest_strength) {
				$lowest_strength = $rule_strength;
			}
		}
		return $lowest_strength;
	}
}
