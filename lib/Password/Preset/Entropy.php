<?php
/**
 * Password_Preset Entropy
 *
 * This interface returns an array of rules based on the great password
 * validation library created by Gary Bell
 * https://gitlab.com/garybell/password-validation
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Preset;

class Entropy {

	/**
	 * Does the given password matches this condition
	 *
	 * @access public
	 * @return array $rules
	 */
	public static function export(): array {
		$rules = [];
		// Numbers only
		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Entropy(\Password\Strength::VULNERABLE));
		$rule->set_strength(\Password\Strength::VULNERABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Entropy(\Password\Strength::INSECURE));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Entropy(\Password\Strength::ACCEPTABLE));
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Entropy(\Password\Strength::GOOD));
		$rule->set_strength(\Password\Strength::GOOD);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Entropy(\Password\Strength::STRONG));
		$rule->set_strength(\Password\Strength::STRONG);
		$rules[] = $rule;

		return $rules;
	}

}

