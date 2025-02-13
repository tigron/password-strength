<?php
/**
 * Password_Preset Zxcvbn
 *
 * This interface returns an array of rules for Zxcvbn password strength check
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Preset;

class Zxcvbn {

	/**
	 * Does the given password matches this condition
	 *
	 * @access public
	 * @return array $rules
	 */
	public static function export(): array {
		$rules = [];

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Zxcvbn(0));
		$rule->set_strength(\Password\Strength::VULNERABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Zxcvbn(1));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Zxcvbn(2));
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Zxcvbn(3));
		$rule->set_strength(\Password\Strength::GOOD);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Zxcvbn(4));
		$rule->set_strength(\Password\Strength::STRONG);
		$rules[] = $rule;

		return $rules;
	}

}

