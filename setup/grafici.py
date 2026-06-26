#!/usr/bin/env python3
"""
grafici.py: genera i cinque grafici dei risultati dal database SQLite degli esperimenti.
Progetto #8 "Intelligent Penetration Testing" (PTEH, UniSA 2025/26). Antonio Di Giorgio.

Uso (dalla venv dell'analisi, con matplotlib installato):
  python ~/pt-privesc/grafici.py --db <file.sqlite3> --out <cartella>
Produce 5 file .png da copiare in Relazione_.../figure/04_risultati/.
"""

import sqlite3
import argparse
import os
import json

import matplotlib
matplotlib.use("Agg")  # backend non interattivo: salva le figure su file senza aprire finestre (necessario in WSL, che non ha display)
import matplotlib.pyplot as plt
import numpy as np


# CONFIGURAZIONE

# Percorsi di default: il database degli esperimenti e la cartella dove salvare le figure.
DB_DEFAULT = os.path.expanduser("~/pt-privesc/results/run.sqlite3")
OUT_DEFAULT = os.path.expanduser("~/pt-privesc/results/figure")

# Ordine fisso dei modelli in tutti i grafici: prima i tre locali, poi il modello cloud.
ORDINE_MODELLI = ["llama3.1:8b", "qwen3:14b-q4_K_M", "gemma4:12b", "gpt-4o"]

# Etichette mostrate nei grafici: accorcio il nome interno di qwen3 per leggibilità.
ETICHETTE_MODELLI = {
    "llama3.1:8b": "llama3.1:8b",
    "qwen3:14b-q4_K_M": "qwen3:14b",
    "gemma4:12b": "gemma4:12b",
    "gpt-4o": "gpt-4o",
}

# Le otto configurazioni di prompt a contesto nativo. Escludo di proposito le repliche
# "_8k" di gpt-4o: servono solo al controllo di equità, non vanno nei grafici principali.
ORDINE_CONFIG = ["history", "baseline", "history_state", "state_only",
                 "history_hint", "baseline_hint", "history_state_hint", "state_only_hint"]

N_SCENARI = 13   # numero di scenari del benchmark (da sc01 a sc13)


# LETTURA E INTERPRETAZIONE DEL DATABASE

def estrai_modello(configuration, fallback):
    """Ricava il nome del modello dal campo JSON 'configuration' del run.

    Il nome vero si trova in configuration, alla voce llm.model. Tutte le varianti
    del nome di Gemma provate durante il progetto vengono ricondotte a un'unica
    etichetta 'gemma4:12b', così nei grafici compare una sola voce. Se il campo non
    è leggibile, si usa il valore 'fallback' passato dal chiamante.
    """
    try:
        cfg = json.loads(configuration) if configuration else {}
        m = cfg.get("llm", {}).get("model") or fallback
    except (json.JSONDecodeError, TypeError):
        m = fallback
    # Normalizza qualunque variante di Gemma a un'unica etichetta
    if m and ("gemma-4" in m or "gemma4" in m):
        return "gemma4:12b"
    return m


def estrai_scenario(configuration):
    """Ricava il numero di scenario (da 1 a 13) dalla porta SSH usata nel run.

    Gli scenari sono mappati sulle porte da 5001 a 5013, quindi lo scenario è la
    porta meno 5000. Unica eccezione: lo scenario 4 gira sulla porta 5099 (rimappata
    per un problema di inoltro della 5004), perciò lo ricostruisco a mano.
    """
    try:
        cfg = json.loads(configuration) if configuration else {}
        porta = int(cfg.get("conn", {}).get("port", 0))
        return 4 if porta == 5099 else porta - 5000
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def carica(db):
    """Legge il database e restituisce i run come lista di tuple semplici.

    Ogni elemento è (modello, configurazione, scenario, successo), dove 'successo'
    vale 1 se il run ha ottenuto root e 0 altrimenti. I run rimasti in stato
    "in progress" (residui di esecuzioni interrotte e poi ripetute) vengono scartati,
    per non falsare il calcolo dei tassi.
    """
    con = sqlite3.connect(db)
    righe = con.execute("SELECT tag, state, configuration FROM runs").fetchall()
    con.close()
    dati = []  # ogni elemento sarà la tupla (modello, config, scenario, successo)
    for tag, state, configuration in righe:
        modello = estrai_modello(configuration, "")
        scen = estrai_scenario(configuration)
        # Successo: lo stato del run contiene la parola "root" (cioè "got root")
        succ = 1 if (state and "root" in state.lower()) else 0
        # Scarta i run ancora "in progress": sono residui, non risultati validi
        if state and "progress" in state.lower():
            continue
        dati.append((modello, tag, scen, succ))
    return dati


def tasso(dati, filtro):
    """Calcola il tasso di successo, in percentuale, sui run che soddisfano 'filtro'.

    'filtro' è una funzione che, dato un run, restituisce True se va incluso nel
    calcolo. Restituisce None quando nessun run soddisfa il filtro, così il chiamante
    può distinguere "zero successi" da "nessun dato disponibile".
    """
    sel = [d for d in dati if filtro(d)]
    if not sel:
        return None
    return 100.0 * sum(d[3] for d in sel) / len(sel)


# GRAFICI

def grafico_tasso_modello(dati, out):
    """Grafico 1: barre del tasso di successo aggregato per ciascun modello.

    Considera solo le configurazioni a contesto nativo, escludendo le repliche "_8k".
    """
    # Tiene solo i modelli effettivamente presenti nel database, nell'ordine fisso
    modelli = [m for m in ORDINE_MODELLI if any(d[0] == m for d in dati)]
    # Per ogni modello calcola il tasso medio sui run non "_8k" (0 se manca il dato)
    valori = [tasso(dati, lambda d, m=m: d[0] == m and not str(d[1]).endswith("_8k")) or 0 for m in modelli]
    fig, ax = plt.subplots(figsize=(7, 4))
    barre = ax.bar([ETICHETTE_MODELLI.get(m, m) for m in modelli], valori,
                   color=["#bdbdbd", "#6baed6", "#74c476", "#fd8d3c"][:len(modelli)])
    # Scrive la percentuale appena sopra ciascuna barra
    for b, v in zip(barre, valori):
        ax.text(b.get_x() + b.get_width() / 2, v + 1, f"{v:.0f}%", ha="center", fontsize=11)
    ax.set_ylabel("Tasso di successo (%)")
    ax.set_ylim(0, max(valori + [10]) * 1.2)
    ax.set_title("Tasso di successo per modello (aggregato)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "tasso_per_modello.png"), dpi=150)
    plt.close(fig)


def _heatmap(matrice, righe_lab, col_lab, titolo, nomefile, out):
    """Disegna e salva una heatmap generica a partire da una matrice di tassi.

    'matrice' è una lista di righe; ogni cella è un tasso (da 0 a 100) oppure None
    se per quella combinazione non ci sono run (in quel caso la cella resta vuota).
    La funzione è condivisa dalla heatmap configurazione-modello e da quella
    scenario-modello.
    """
    fig, ax = plt.subplots(figsize=(1.6 + 1.1 * len(col_lab), 0.5 + 0.45 * len(righe_lab)))
    # Converte la matrice in array NumPy, trasformando i None in NaN (celle vuote)
    M = np.array([[np.nan if v is None else v for v in r] for r in matrice], dtype=float)
    # Colori dal giallo (tasso basso) al rosso (alto); scala fissa 0-100 per confronti coerenti
    im = ax.imshow(M, cmap="YlOrRd", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(col_lab)), col_lab, rotation=0)
    ax.set_yticks(range(len(righe_lab)), righe_lab)
    # Scrive il valore in ogni cella, in bianco sulle celle scure per restare leggibile
    for i in range(len(righe_lab)):
        for j in range(len(col_lab)):
            if not np.isnan(M[i, j]):
                ax.text(j, i, f"{M[i, j]:.0f}", ha="center", va="center", fontsize=9,
                        color="black" if M[i, j] < 55 else "white")
    ax.set_title(titolo)
    fig.colorbar(im, ax=ax, label="successo (%)", fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(os.path.join(out, nomefile), dpi=150)
    plt.close(fig)


def grafico_pivot_config(dati, out):
    """Grafico 2: heatmap del tasso di successo incrociando configurazione e modello."""
    modelli = [m for m in ORDINE_MODELLI if any(d[0] == m for d in dati)]
    # Tiene solo le configurazioni presenti, nell'ordine logico definito sopra
    configs = [c for c in ORDINE_CONFIG if any(d[1] == c for d in dati)]
    # Costruisce la matrice: una riga per configurazione, una colonna per modello
    M = [[tasso(dati, lambda d, m=m, c=c: d[0] == m and d[1] == c) for m in modelli] for c in configs]
    _heatmap(M, configs, [ETICHETTE_MODELLI.get(m, m) for m in modelli],
             "Tasso di successo per configurazione x modello", "pivot_config_modello.png", out)


def grafico_heatmap_scenario(dati, out):
    """Grafico 3: heatmap del tasso di successo incrociando scenario e modello.

    È l'equivalente del "vulnerability breakdown" di un report di sicurezza: mostra
    quali vettori (scenari) ciascun modello riesce a violare.
    """
    modelli = [m for m in ORDINE_MODELLI if any(d[0] == m for d in dati)]
    scen = list(range(1, N_SCENARI + 1))
    # Matrice: una riga per scenario, una colonna per modello (solo run a contesto nativo)
    M = [[tasso(dati, lambda d, m=m, s=s: d[0] == m and d[2] == s and not str(d[1]).endswith("_8k"))
          for m in modelli] for s in scen]
    _heatmap(M, [f"sc{ s:02d}" for s in scen], [ETICHETTE_MODELLI.get(m, m) for m in modelli],
             "Tasso di successo per scenario x modello", "heatmap_scenario_modello.png", out)


def grafico_effetto_hint(dati, out):
    """Grafico 4: per ogni modello, confronto tra il tasso senza hint e con hint.

    Affianca due barre per modello, così si vede a colpo d'occhio quanto il
    suggerimento aiuta. Considera solo i run a contesto nativo.
    """
    modelli = [m for m in ORDINE_MODELLI if any(d[0] == m for d in dati)]
    # Tasso medio sui run SENZA hint (escludendo le repliche "_8k")
    no_hint = [tasso(dati, lambda d, m=m: d[0] == m and isinstance(d[1], str)
                     and "hint" not in d[1] and not d[1].endswith("_8k")) or 0 for m in modelli]
    # Tasso medio sui run CON hint (le configurazioni che hanno "hint" nel nome)
    con_hint = [tasso(dati, lambda d, m=m: d[0] == m and isinstance(d[1], str)
                      and "hint" in d[1] and not d[1].endswith("_8k")) or 0 for m in modelli]
    x = np.arange(len(modelli)); w = 0.38   # posizioni sull'asse x e larghezza delle barre
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(x - w / 2, no_hint, w, label="senza hint", color="#9ecae1")
    ax.bar(x + w / 2, con_hint, w, label="con hint", color="#3182bd")
    ax.set_xticks(x, [ETICHETTE_MODELLI.get(m, m) for m in modelli])
    ax.set_ylabel("Tasso di successo medio (%)")
    ax.set_title("Effetto dell'hint per modello")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out, "effetto_hint.png"), dpi=150)
    plt.close(fig)


def grafico_matrice_rischio(dati, out):
    """Grafico 5: matrice di rischio degli scenari.

    L'impatto è lo stesso per tutti i vettori (portano tutti a root, quindi critico),
    perciò l'unico asse che varia è la probabilità di sfruttamento. La stimo con il
    miglior tasso ottenuto da uno qualunque dei modelli su quello scenario, cioè il
    caso peggiore dal punto di vista del difensore. Ogni scenario diventa un punto
    lungo l'asse della probabilità.
    """
    scen = list(range(1, N_SCENARI + 1))
    # Per ogni scenario prende il tasso più alto tra tutti i modelli (caso peggiore)
    prob = []
    for s in scen:
        t = [tasso(dati, lambda d, m=m, s=s: d[0] == m and d[2] == s) or 0 for m in ORDINE_MODELLI]
        prob.append(max(t))
    fig, ax = plt.subplots(figsize=(8, 3.2))
    # Bande di sfondo per le fasce di esposizione: verde (nulla), giallo (media), rosso (alta)
    ax.axvspan(0, 1, color="#2ca25f", alpha=0.12)
    ax.axvspan(1, 50, color="#fec44f", alpha=0.15)
    ax.axvspan(50, 100, color="#de2d26", alpha=0.15)
    ax.scatter(prob, [1] * len(scen), s=60, color="#de2d26", zorder=3)
    # Etichetta ogni punto con il nome dello scenario
    for s, p in zip(scen, prob):
        ax.annotate(f"sc{s:02d}", (p, 1), textcoords="offset points", xytext=(0, 8),
                    ha="center", fontsize=8, rotation=45)
    ax.set_yticks([1], ["Impatto: root (critico)"])
    ax.set_xlim(-2, 102); ax.set_ylim(0.5, 1.6)
    ax.set_xlabel("Probabilita' di sfruttamento = tasso di violazione osservato (%)")
    ax.set_title("Matrice di rischio (impatto critico per tutti i vettori)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "matrice_rischio.png"), dpi=150)
    plt.close(fig)


# PROGRAMMA PRINCIPALE

def main():
    """Legge gli argomenti, carica i dati dal database e genera le cinque figure."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_DEFAULT)    # database da leggere
    ap.add_argument("--out", default=OUT_DEFAULT)  # cartella dove salvare i file .png
    args = ap.parse_args()
    # Crea la cartella di uscita se non esiste (comprese le eventuali cartelle intermedie)
    os.makedirs(args.out, exist_ok=True)
    dati = carica(args.db)
    print(f"Caricati {len(dati)} run da {args.db}")
    # Genera le cinque figure una dopo l'altra
    grafico_tasso_modello(dati, args.out)
    grafico_pivot_config(dati, args.out)
    grafico_heatmap_scenario(dati, args.out)
    grafico_effetto_hint(dati, args.out)
    grafico_matrice_rischio(dati, args.out)
    print(f"Figure salvate in {args.out}")
    print("Copiale poi in Relazione_.../figure/04_risultati/")


# Esegue main() solo quando il file viene lanciato direttamente (non quando è importato)
if __name__ == "__main__":
    main()
