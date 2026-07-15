---
title: "Adversarial ML Attacks (Evasion, Poisoning, Inversion, Theft)"
type: technique
tags: [ai, ml, adversarial, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-ai]
---

# Adversarial ML Attacks (Evasion, Poisoning, Inversion, Theft)

## What it is

The classic ML-security taxonomy (OWASP ML Top 10, Google SAIF, MITRE ATLAS) for any deployed classifier, detector, or predictive model, including the ML models used inside security products. Distinct from LLM-application attacks (see [[llm-attacks]]): this is attacks against the model itself, its training data, its outputs, and its decision boundary.

## Attack classes

- Input manipulation / evasion (adversarial examples): add small, often invisible perturbations to a live input so the model misclassifies. Example: stickers on a stop sign read as a speed-limit sign; a malware binary crafted to score "benign" past an ML detector. Test transferability of samples across models.
- Data poisoning: inject mislabeled or biased samples into the training or fine-tune set to implant a backdoor or degrade accuracy (for example malware labeled benign in an AV corpus). Model skewing is the subtler variant that shifts outputs toward an attacker goal.
- Transfer-learning backdoor: plant hidden trigger logic in a pre-trained backbone so it survives fine-tuning on the victim task. High relevance to the model-hub supply chain.
- Model inversion: probe outputs to reconstruct sensitive training inputs (for example recreate a patient image from a diagnostic model's predictions).
- Membership inference: detect whether a specific record was in the training set by exploiting confidence differences, a privacy and compliance breach.
- Model theft / extraction: query the model enough to clone its decision boundary and IP (harvest Q&A pairs from an ML-as-a-Service API to distill an equivalent local model). Query-rate anomalies are the main tell.
- Output integrity: tamper with predictions in transit (not the model) so a downstream system acts on a flipped verdict (malicious flipped to benign before quarantine).
- Model poisoning (weights): with write access, directly edit parameters in a deployed model to change behavior for chosen inputs.

## Methodology

When a target exposes an ML endpoint: enumerate the model type and output verbosity (confidence scores enable inversion and membership inference), test evasion with perturbed inputs, probe for extraction via bulk queries, and map training-data provenance and pre-trained dependencies for poisoning and backdoor risk. Use MITRE ATLAS to frame the tactics.

## Tools

- adversarial-robustness-toolbox: evasion, poisoning, inversion, and extraction attack/defence library.
- garak: covers the LLM subset of adversarial testing.

## Sources

- HackTricks (AI): adversarial-ML taxonomy (evasion, poisoning, transfer-learning backdoor, inversion, membership inference, extraction, output integrity, weight poisoning).
- Related: [[llm-attacks]], [[ml-model-deserialization]], [[supply-chain-attacks]].
