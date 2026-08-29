from llm_reasoner import LLMReasoner

def build_reasoning_request(finding, source, reproduction):
    return LLMReasoner().reason_and_patch(finding, source, reproduction)

if __name__ == "__main__":
    print("VAJRA LLM reasoning layer loaded.")
    print("Configure LLM_PROVIDER=openai and LLM_API_KEY for live reasoning.")
