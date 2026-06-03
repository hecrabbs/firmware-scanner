from google import genai


def analyze(prev_interaction, client):
    print(f"\n[*] Running agentic analysis...")

    # Continue the investigation based on what the tools returned
    final_assessment_prompt = (
        "Based on the files you have inspected, compile a final "
        "vulnerability analysis report. Be consise and include the following "
        "sections:\n"
        "1. Bullet points listing any critical issues which expose the "
        "firmware to botnet takeovers.\n"
        "2. How those issues would be exploited for a botnet takeover.\n"
        "3. A rating from 1-10 on how secure this firmware is."
    )

    final_report = client.interactions.create(
        model='gemini-2.5-flash-lite', # Switch to Pro here for higher quality synthesis
        input=final_assessment_prompt,
        previous_interaction_id=prev_interaction.id, # Maintains the state of the files it read
    )

    return final_report
