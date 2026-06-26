# LLM-Privilege_Escalation

> Progetto universitario per il corso di Penetration Testing and Ethical Hacking
> Università degli Studi di Salerno, A.A. 2025/2026

Replica ed estensione dello studio di Happe & Cito (*Getting pwn'd by AI*, ESEC/FSE 2023) sulla
privilege escalation autonoma condotta da Large Language Model. Un LLM, pilotato dal framework
hackingBuddyGPT, tenta in autonomia la privilege escalation via SSH sui tredici scenari Docker del
benchmark Got Root?, partendo da un utente non privilegiato con l'obiettivo di ottenere i privilegi
di root.

## Cosa fa il progetto

Confronta un modello cloud (GPT-4o) con tre modelli locali eseguibili su hardware consumer
(qwen3:14b, llama3.1:8b, gemma4:12b), facendo variare la strategia di prompt lungo otto
configurazioni (cronologia dei comandi, stato sintetico, suggerimento sul vettore) e controllando
l'equità della dimensione del contesto tra cloud e locali. In totale 524 esecuzioni (una per
combinazione modello x configurazione x scenario), limite di 20 turni ciascuna.

## Risultati principali

| Modello | Tipo | Tasso di successo |
|---|---|---|
| gemma4:12b | locale | **30%** |
| gpt-4o | cloud | 26% |
| qwen3:14b | locale | 22% |
| llama3.1:8b | locale | 0% (rifiuta il task per safety) |

Il modello più capace è uno dei locali, gemma4:12b, che supera GPT-4o. La cronologia dei comandi è
condizione necessaria al successo (in configurazione `baseline`, senza memoria, il tasso è 0% per
tutti i modelli); il suggerimento sul vettore è la leva più efficace. Dettagli, metodologia e
contromisure nel report completo.

## Tecnologie e strumenti

- [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) — framework che orchestra il ciclo agente-LLM via SSH
- [benchmark-privesc-linux ("Got Root?")](https://github.com/ipa-lab/benchmark-privesc-linux) — 13 scenari Docker di privilege escalation
- [Ollama](https://ollama.com/) — esecuzione dei modelli locali (qwen3:14b, llama3.1:8b, gemma4:12b)
- OpenAI API — modello cloud GPT-4o
- Python 3.12, pandas, matplotlib — estrazione metriche e grafici dal database SQLite dei log

## Struttura del repository

```
.
├── Report_Progetto_PTEH_AntonioDiGiorgio.pdf            # report completo
├── Presentazione_Progetto_PTEH_AntonioDiGiorgio.pdf      # slide per l'orale
├── Doc_Replicabilità_Progetto_PTEH_AntonioDiGiorgio.pdf  # guida alla riproduzione
├── articoli/                  # paper di riferimento (Happe & Cito)
├── setup/
│   ├── runner.sh               # automatizza le 524 esecuzioni
│   ├── analisi.py               # estrae le metriche dal database SQLite
│   ├── grafici.py                # genera le figure dei risultati
│   ├── requirements.txt
│   └── env.esempio.txt          # configurazione di esempio (.env)
└── risultati/                  # log, checkpoint e database dei run
```

## Installazione e utilizzo

Guida completa, passo per passo, nel Documento di Replicabilità incluso nella repo. In sintesi:

```bash
# 1. Ambiente Python di hackingBuddyGPT
uv venv --python 3.12 .venv && source .venv/bin/activate
uv pip install -e .
pip install -r setup/requirements.txt

# 2. Configurazione (.env), basata su setup/env.esempio.txt
#    la chiave API OpenAI NON va mai versionata

# 3. Esecuzione della campagna completa (524 run)
export OPENAI_API_KEY="sk-..."
bash setup/runner.sh

# 4. Analisi e grafici
python setup/analisi.py --dettaglio > risultati/analisi.txt
python setup/grafici.py --db risultati/run.sqlite3 --out risultati/figure
```

Richiede WSL2 (Ubuntu) per hackingBuddyGPT e i container del benchmark, Ollama nativo su Windows
con GPU per i modelli locali, una API key OpenAI per GPT-4o.

## Considerazioni etiche

L'intera sperimentazione è condotta su un benchmark isolato e sintetico (container Docker creati
appositamente), senza alcun sistema reale, dato di terzi o rete esterna coinvolti. Finalità
esclusivamente didattica e di ricerca.

## Riferimenti principali

- Happe, A. & Cito, J. — *Getting pwn'd by AI: Penetration testing with large language models*, ESEC/FSE 2023
- Happe, A., Kaplan, A. & Cito, J. — *LLMs as Hackers: Autonomous linux privilege escalation attacks*, Empirical Software Engineering, 2026
- Happe, A. & Cito, J. — *Got Root? A linux priv-esc benchmark*, arXiv:2405.02106, 2024

## Licenza

Progetto accademico, Università degli Studi di Salerno. Finalità esclusivamente didattica e di ricerca.
