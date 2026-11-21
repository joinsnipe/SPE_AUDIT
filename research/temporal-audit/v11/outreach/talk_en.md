# What could an AI say on 1 January 2022?

**Rubén Abella · SPE Audit**

Speaker script, 4 min 45 s. Seven slides. The timings include pauses and slide changes. The example answers come from a constructed study.

### 0:00–0:32 · 1. The question

Imagine it is New Year’s Day, 2022. Someone asks about the DART spacecraft and gets this answer: “DART hit Dimorphos in 2022.” We know today that the impact happened. But suppose somebody uses that sentence as evidence of what was known in January. Would you accept it? I published the case, its documents and the code through SPE Audit. You have what you need to challenge my reading.

### 0:32–1:08 · 2. The timeline

NASA had announced the launch in late 2021 and described the aim of the mission. The impact happened on 26 September 2022. In January, a writer could describe the plan. Describing the impact as complete adds an outcome that had yet to happen. I wrote this particular sentence for case `dart-09`. Notice the year. The year in the sentence is exactly the year of the cutoff. A program that just compares those two numbers lets the assertion pass.

### 1:08–1:46 · 3. The record

What would I want to keep if a customer challenged that answer? The exact request received by the local sender, the cutoff, the rule used to select the documents, and the text returned. A third party with a separately retained digest can check whether the recorded bytes changed. Deciding what the sentence asserts requires reading it beside dated evidence. Attributing the statement to a training example or a particular retrieved document requires further observations. An auditor should be able to answer those three questions separately.

### 1:46–2:27 · 4. The first 96 answers

I worked with 96 constructed cases. In 32 of them, the answer described a later outcome as already complete. The first dated matcher in the study detected 24 of those 32 positives, or 75 percent. It reached an automatic decision on 84 of the 96 cases, giving it 87.5 percent coverage. Twelve cases went to review. The denominators matter. One measures how many positives the method detected. The other measures how many cases received a decision. Calling either number an overall reliability score would give a buyer an answer to a question the study never tested.

### 2:27–3:01 · 5. A change in wording

Then I used 16 sentences written in a separate phase about the same missions. Eight still asserted a completed event after the cutoff. The same matcher detected zero of eight and sent fourteen of the sixteen for review. Its only two automatic decisions were controls. The study did not measure what a human reviewer would have concluded in those fourteen cases. This is the number I would want beside any proposal to automate an audit: how much work comes back to people when the language changes?

### 3:01–4:02 · 6. One code, two routes

For the supplement I built forty matched triplets around fictional archive tickets. Three local programs received the same question with the target document present, absent or replaced. One program read the document. It returned the target forty times when present and never when absent. Replacing the document made it return the replacement ticket forty times. Another program always gave a generic reply. A third received the target through a separate input. It was right forty times out of forty even with the document absent, and again with the replacement present.

That makes 360 local calls with forty matched units per contrast. I know which routes these programs use because I deliberately built them. When all we have is an old answer, seeing the same rare code admits more than one explanation. These forty cases observed neither a remote provider’s training data nor its execution.

### 4:02–4:45 · 7. A pilot open to challenge

If an organization wants to try this with its own service, I would start with one dated question and a set of documents it can share. We can agree where capture takes place, integrate the adapter under the relevant license terms and produce a report with examples, coverage, disagreements and review workload. The study and verifier are available before anyone buys a service. I would like the first conversation to concern one specific case. Bring an answer you would challenge today. Let’s agree what evidence could settle the question and what would remain open after the audit.

### Three alternative openings

- **Product owners.** “If a customer challenged a January answer today, could you recover the exact documents your application supplied?”
- **Auditors.** “A sentence can be historically accurate and still lie outside the date the system was asked to respect. Let’s reconstruct one.”
- **General audiences.** “Travel back to New Year’s Day, 2022. A spacecraft is on its way to an asteroid. Can we already write that it struck?”

### Three alternative closings

- **Demonstration.** “Choose the date, read both sources and run the verifier. Then we can discuss the sentence with the same material in front of us.”
- **Research.** “I welcome replications that change the wording or add new events. Please report which cases still needed review.”
- **Technical pilot.** “Bring one case and one reviewer. We can define what to record, what decision to evaluate and what stronger evidence a stronger claim would need.”

[Presentation PDF](slides_en.pdf) · [Research paper](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/PAPER_EN.pdf) · [Archive-ticket intervention](https://github.com/joinsnipe/SPE_AUDIT/tree/main/research/temporal-audit/v11/interventions) · [Project license](https://github.com/joinsnipe/SPE_AUDIT/blob/main/LICENSE)
