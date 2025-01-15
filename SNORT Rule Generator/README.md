# SNORT Rule Generator

This Python script generates a SNORT rule based on user input and saves it to a file.

**Usage:**
1. Install Python if it's not already installed on your system.
2. Download the script and save it to a directory of your choice.
3. Open a command prompt or terminal and navigate to the directory where the script is saved.
4. Run the script by typing python snort_rule_generator.py and pressing Enter.
5. Follow the prompts to enter the required inputs for the SNORT rule.

The generated SNORT rule will be saved to a file named "snort_rules.txt" in the same directory as the script.

**Input Validation:**

The script validates user input to ensure that the generated SNORT rule is formatted correctly. The following input is validated:

- IP addresses: The script uses a regular expression to validate that IP addresses are in the correct format (e.g. "192.168.0.1").
- Port numbers: The script ensures that port numbers are integers between 0 and 65535.
- If any of the input is invalid, the script will display an error message and prompt the user to enter the input again.

**Purpose:**

This script is intended for users who need to generate SNORT rules but want an easier and quicker way to do so. By using this script, users can avoid the tedious process of manually creating SNORT rules and ensure that the generated rule is correctly formatted.

**License:**

This script is licensed under the MIT License. See the LICENSE file for more information.