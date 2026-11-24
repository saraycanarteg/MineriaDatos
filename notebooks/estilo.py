"""Estilo común de los gráficos de los notebooks."""

import matplotlib.pyplot as plt

AZUL = "#2a78d6"
NARANJA = "#eb6834"
AGUA = "#1baf7a"
GRIS = "#8a8983"
TEXTO = "#33322e"


def aplicar():
    plt.rcParams.update({
        "figure.dpi": 110,
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
        "font.size": 10,
        "axes.edgecolor": "#c9c8c1",
        "axes.labelcolor": TEXTO,
        "axes.titleweight": "bold",
        "axes.titlesize": 11,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": "#e6e5df",
        "grid.linewidth": 0.8,
        "axes.axisbelow": True,
        "xtick.color": TEXTO,
        "ytick.color": TEXTO,
        "legend.frameon": False,
    })


def etiquetar_barras(ax, barras, formato="{:.0f}", horizontal=True):
    """Escribe el valor al final de cada barra, en color de texto."""
    for b in barras:
        valor = b.get_width() if horizontal else b.get_height()
        if valor == 0:
            continue
        if horizontal:
            ax.text(valor, b.get_y() + b.get_height() / 2, " " + formato.format(valor),
                    va="center", ha="left", fontsize=8, color=TEXTO)
        else:
            ax.text(b.get_x() + b.get_width() / 2, valor, formato.format(valor),
                    va="bottom", ha="center", fontsize=8, color=TEXTO)
