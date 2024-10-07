import os
from transformers import AutoModelForCausalLM, AutoTokenizer
from codeshield.cs import CodeShield

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
        

# Load a causal language model for code generation from Hugging Face
model_name = "codellama/CodeLlama-13b-Instruct-hf"  # Use a suitable causal model like Code LLaMA
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

# Define the prompt for code generation
prompt = "Output a single python function which calculates the md5 hash of a string provided as an argument to the function. Output only the code and nothing else."

# Tokenize the input prompt
inputs = tokenizer(prompt, return_tensors="pt")

# Generate output (limit the length to avoid excessive output)
output_tokens = model.generate(**inputs, max_length=100)

# Decode the output tokens to get the generated code
llm_output_code = tokenizer.decode(output_tokens[0], skip_special_tokens=True)

# Print the generated code
print(llm_output_code)

# If you need to scan or process the output
await scan_llm_output(llm_output_code)  # Ensure scan_llm_output is defined elsewhere
