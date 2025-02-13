<?php
/**
 * Password_Preset Hive2024
 *
 * This interface returns an array of rules for the Hive 2024 password table
 * https://www.hivesystems.com/blog/are-your-passwords-in-the-green
 *
 * Be aware that this preset cannot be used standalone. If could help you
 * in creating a good ruleset, but it does not cover all use cases:
 * - password table does not mention the combination of numbers and symbols. No
 *   rule will therefore match such a given password
 * - password table does not mention anything about passphrases. These contain
 *   spaces (which are considered a symbol) and can only be combined with 
 *   uppercase, lowercase and numbers. There is no mention about passphrases
 *   that contain only lowercase and spaces.
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Preset;

class Hive2024 {

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
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(false));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));
		$rule->add_condition(new \Password\Condition\Length\Max(6));
		$rule->set_strength(\Password\Strength::VULNERABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(false));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(7));		
		$rule->add_condition(new \Password\Condition\Length\Max(14));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(false));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(15));		
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;

		// Lowercase letters				
		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Max(4));
		$rule->set_strength(\Password\Strength::VULNERABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(5));		
		$rule->add_condition(new \Password\Condition\Length\Max(9));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(10));		
		$rule->add_condition(new \Password\Condition\Length\Max(13));
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(14));		
		$rule->add_condition(new \Password\Condition\Length\Max(16));
		$rule->set_strength(\Password\Strength::GOOD);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(false));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(17));		
		$rule->set_strength(\Password\Strength::STRONG);
		$rules[] = $rule;

		// Upper and Lowercase letters		
		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Max(8));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(9));		
		$rule->add_condition(new \Password\Condition\Length\Max(11));
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(12));		
		$rule->add_condition(new \Password\Condition\Length\Max(13));
		$rule->set_strength(\Password\Strength::GOOD);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(false));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(14));		
		$rule->set_strength(\Password\Strength::STRONG);
		$rules[] = $rule;

		// Numbers, Upper and Lowercase letters
		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Max(7));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(8));				
		$rule->add_condition(new \Password\Condition\Length\Max(10));
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;		

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(11));				
		$rule->add_condition(new \Password\Condition\Length\Max(13));
		$rule->set_strength(\Password\Strength::GOOD);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(false));		
		$rule->add_condition(new \Password\Condition\Length\Min(14));				
		$rule->set_strength(\Password\Strength::STRONG);
		$rules[] = $rule;		

		// Numbers, Upper and Lowercase letters, Symbols
		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(true));						
		$rule->add_condition(new \Password\Condition\Length\Max(7));
		$rule->set_strength(\Password\Strength::INSECURE);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(true));		
		$rule->add_condition(new \Password\Condition\Length\Min(8));						
		$rule->add_condition(new \Password\Condition\Length\Max(10));
		$rule->set_strength(\Password\Strength::ACCEPTABLE);
		$rules[] = $rule;		

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(true));		
		$rule->add_condition(new \Password\Condition\Length\Min(11));						
		$rule->add_condition(new \Password\Condition\Length\Max(13));
		$rule->set_strength(\Password\Strength::GOOD);
		$rules[] = $rule;

		$rule = new \Password\Rule();
		$rule->add_condition(new \Password\Condition\Number(true));				
		$rule->add_condition(new \Password\Condition\Lowercase(true));
		$rule->add_condition(new \Password\Condition\Uppercase(true));
		$rule->add_condition(new \Password\Condition\Symbol(true));		
		$rule->add_condition(new \Password\Condition\Length\Min(14));						
		$rule->set_strength(\Password\Strength::STRONG);
		$rules[] = $rule;

		return $rules;		
	}

}

