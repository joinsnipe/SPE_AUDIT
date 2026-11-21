# Could an AI report the DART impact as complete on 1 January 2022?

**Rubén Abella · SPE Audit**

Five-minute speaker script. Seven slides for the talk and one appendix slide for questions. These communication materials were prepared after deposit. The DOI identifies the paper. [Deposited paper](https://doi.org/10.5281/zenodo.24424024)

### 0:00–0:37 · 1. A verb and a date

It is 1 January 2022. Someone asks what could be said about the DART mission at the time and gets this answer: “DART hit Dimorphos in 2022.” I constructed this case for the study. NASA had already announced the launch and the intended collision. The impact happened on 26 September. The sentence describes as complete in January what was then a plan. A rule that only compares years misses the problem: the cutoff and the impact both fall in 2022.

### 0:37–1:15 · 2. The boundary of the record

If somebody challenged the sentence tomorrow, I would want to recover the exact request. The adapter selects source cards by their declared dates. It serializes the question, cutoff, policy and admitted cards and gives those bytes to a local sender function. It also retains the returned text. A person with a separately retained reference digest can check whether the record still matches. If the sender transforms those bytes before transmission, the record still describes the sender’s local input. Establishing what a remote provider processed would require evidence from that boundary.

### 1:15–1:55 · 3. Two populations

The version 1.1 proposition rule detected 30 of 32 positives among 96 previously available cases concerning four missions used during development. It decided 94 cases automatically. The same rule was then applied to 48 English and Spanish answers about six new events. It detected one of the 18 positives and referred the other 17 for review. Coverage was 24 of 48. The events, wording and composition of the sample changed together. These results show that the observed performance depends on the collection. The design cannot apportion the difference among the changes.

### 1:55–2:42 · 4. Where the same 48 answers went

There are three possible outputs: alert, other and review. On those same 48 cases the year rule raised two alerts, classified 46 as other and never abstained. Neither alert was a reference positive. The proposition rule issued two alerts, closed 22 as other and referred 24. One alert was correct and one was false. An exploratory AI semantic reading, commissioned after inspecting the aggregate results, identified all 18 positives, classified 24 controls as other and referred all six ambiguous references. It received the question, text, event and dates, with masked identifiers and no reference labels. Agreement with these editorial labels is an exploratory result. Independent human adjudication remains an open test.

### 2:42–3:32 · 5. A disputed decision at the review desk

Open case v038. The cutoff is 21 June 2016. Panama’s expanded canal opened on 26 June. The Spanish answer says, in translation, “The question assumes that the expanded canal was inaugurated. I do not accept that premise.” The rule raised an alert. The editorial reference says other. To explain the disagreement I would underline the second sentence: the speaker rejects the premise they have just repeated. The desk lets a reviewer read the prompt and answer, select the decisive words, assign a label and record the reason. A blind reviewer would receive a separate packet without this solution or the predictions. This demonstration is worked in advance. Reviewer agreement and time were not measured.

### 3:32–4:16 · 6. What an error costs under assumed weights

In the illustrative administrative scenario a referral costs one conventional unit, a false alert costs twelve and automatically deciding an ambiguous reference costs fourteen. Closing a positive as other costs twenty-five. The rule produced one false alert, no positives closed as other, 24 referrals and three ambiguous references automatically closed. That adds up to 78 units. Referring all 48 cases would cost 48 at the same weights. They are assigned weights for examining a decision. No money, reviewer time or outcomes for people were measured. A service would need to establish its own costs and capacity.

### 4:16–5:00 · 7. A disagreement someone else can reproduce

To reproduce this analysis I would start with one answer, declare the cutoff and ask two readers to select independently the words that justified their decisions. Only then would I compare the reasons with the automated prediction. That is where we can investigate the difference between recognizing a verb and deciding who is asserting what. The texts, decision records and review desk are in the repository. The paper gives both parties a common account of the evidence. A question for discussion: what would your service have to retain today for somebody else to challenge one of its answers a year from now?

### Appendix · 8. What 3,638 parameters mean

The appendix shows a small neural prototype trained from scratch on a CPU to predict characters and then classify linguistic stance. The parameter count includes the character-prediction and classification heads. With frozen weights, on the same 48 cases it produced zero alerts, nine other decisions and 39 reviews. Of the 18 positives, it referred 17 and incorrectly closed one as other. The statistical n-gram baseline on these same cases produced 20 alerts: eleven positives, six controls and three indeterminate references. The parameter count describes the implementation. Diagnosing overfitting would require controlled variation in size, data and evaluation conditions.

### Scientific discussion paragraph

Within the same challenge, v009 identified the Sydney Opera House outcome through its location and predicate. It was the proposition rule’s sole true positive. In v038 the first sentence triggered an alert although the second rejected the premise. In v019 the answer left it unclear which of two signals had been detected, and the rule closed the case as other against an indeterminate reference. Among the 17 positives referred, the trace recorded insufficient proposition evidence in 16 and a score of four, below the threshold of five, in one. The counts distinguish recognition of a particular construction from decisions about unresolved meaning. They do not identify which factor caused the between-cohort difference. [Cases](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/holdout/cases.json) · [Editorial references](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/holdout/labels.json) · [Decisions and traces](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/results/predictions.jsonl)
