# Usage report

This is the run that produced the repository-root `output.csv` (518 cases). Status decisions and steps are Python rules. The only model calls are screenshot reads. Their JSON is cached, and `python3 code/main.py` does not call the model again.

## Model

| Provider | Model | Calls | Input tokens | Output tokens | Thinking tokens |
| --- | --- | --- | --- | --- | --- |
| Google Gemini API | gemma-4-26b-a4b-it | 10 | 4,710 | 2,104 | 20,237 |

One further screenshot, `evidence_46`, returned no body before the 90 second limit. That attempt is not in the token counts because the API returned no usage metadata.

Input + output + thinking = 27,051 tokens.

## Per case

The 10 calls are shared by all 518 cases.

| | Tokens |
| --- | --- |
| Total | 27,051 |
| Average per case | 52.2 |
| Average per model call | 2,705.1 |

Rules code made 0 model calls while writing `output.csv`.

## Cost

The API response did not include a price. No rate card is configured in this repository. Estimated cost for these 10 calls is $0.00, and the average per case is $0.00.
