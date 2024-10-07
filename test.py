# import os
# from transformers import AutoModelForCausalLM, AutoTokenizer
import asyncio
from codeshield.cs import CodeShield
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

async def scan_llm_output(llm_output_code):
    result = await CodeShield.scan_code(llm_output_code)
    if result.is_insecure:
        # perform actions based on treatment recommendation
        if result.recommended_treatment == "block":
            llm_output_code = "*** Code Security issues found, blocking the code ***"
        if result.recommended_treatment == "warn":
            llm_output_code = llm_output_code + "*** Warning: The generated snippit contains insecure code ***"
    summary = "Security issue detected" if result.is_insecure else "No issues found"

    print("## LLM output after treatment")
    print("\t %s \n" % llm_output_code)
    
    print ("## Results:\n")
    print("\t %s" % (summary))
    print("\t Recommended treatment: %s\n" % result.recommended_treatment)

    print ("## Details:\n")
    if len(result.issues_found) > 0:
        issue = result.issues_found[0]
        print ("\tIssue found: \n\t\tPattern id: %s \n\t\tDescription: %s \n\t\tSeverity: %s \n\t\tLine number: %s" % (issue.pattern_id, issue.description, issue.severity, issue.line))
        



class IBMGraniteLLM:
    def __init__(self):
        self.model_name = "ibm-granite/granite-3b-code-base"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(self.model_name)

    def query(self, prompt):
        inputs = self.tokenizer(prompt, return_tensors="pt")
        outputs = self.model.generate(inputs["input_ids"], max_length=100)
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response

# Example usage
llm = IBMGraniteLLM()
# print(llm.query("Output a single python function which calculates the md5 hash of a string provided as an argument to the function. Output only the code and nothing else."))

llm_output_code = llm.query("How do I connect to a database in Python using MySQL with hardcoded credentials?")
# Print the generated code
# print(llm_output_code)

# If you need to scan or process the output
asyncio.run(scan_llm_output(llm_output_code))  # Ensure scan_llm_output is defined elsewhere
