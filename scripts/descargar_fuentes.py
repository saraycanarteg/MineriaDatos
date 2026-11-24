"""
Descarga las fuentes públicas usadas en la fase Sample.

Los repositorios se clonan en data/raw/ (carpeta ignorada por git) y se fijan
en el commit con el que se construyó el dataset, para que el muestreo sea
reproducible aunque los proyectos sigan evolucionando.

Uso:
    python scripts/descargar_fuentes.py
"""

import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
DESTINO = RAIZ / "data" / "raw"

FUENTES = {
    "BenchmarkJava": ("https://github.com/OWASP-Benchmark/BenchmarkJava.git",
                      "10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17"),
    "BenchmarkPython": ("https://github.com/OWASP-Benchmark/BenchmarkPython.git",
                        "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"),
}


def main():
    DESTINO.mkdir(parents=True, exist_ok=True)
    for nombre, (url, commit) in FUENTES.items():
        carpeta = DESTINO / nombre
        if not carpeta.exists():
            subprocess.run(["git", "clone", "--quiet", url, str(carpeta)], check=True)
        subprocess.run(["git", "-C", str(carpeta), "checkout", "--quiet", commit], check=True)
        print(f"{nombre}: {commit[:10]}")


if __name__ == "__main__":
    main()
