# VulnMiner

Herramienta de minería de datos para clasificar posibles vulnerabilidades en proyectos de microservicios según OWASP Top 10:2025 y OWASP API Security Top 10:2023, desarrollada con la metodología SEMMA.

Laboratorio 1 de Desarrollo de Software Seguro, Universidad de las Fuerzas Armadas ESPE.

## Estado del avance

| Fase | Estado | Dónde está |
|---|---|---|
| 1. Sample | Completa | `scripts/descargar_fuentes.py`, `scripts/construir_dataset.py`, `notebooks/01_sample.ipynb`, `docs/fase1_sample.md` |
| 2. Explore | Completa | `notebooks/02_explore.ipynb`, `reports/figures/` |
| 3. Modify | Completa | `vulnminer/features.py`, `scripts/preprocesar.py`, `scripts/auditar_sesgo.py`, `notebooks/03_modify.ipynb` |
| 4. Model | Pendiente | |
| 5. Assess | Pendiente | |
| CLI y reportes | Pendiente | |

## Estructura

```
data/
  dataset_vulnerabilidades.csv   dataset etiquetado (1541 registros)
  mapeo_cwe_owasp.csv            correspondencia CWE -> OWASP 2025 / API 2023
  processed/                     matrices de características y etiquetas por partición
  raw/                           repositorios fuente (no versionado, se descarga)
docs/                            documentación de cada fase
models/preprocesador.joblib      pipeline de preprocesamiento ajustado con train
notebooks/                       un notebook por fase SEMMA
reports/figures/                 gráficos generados por los notebooks
scripts/                         construcción del dataset y preprocesamiento
vulnminer/                       paquete reutilizable (catálogo OWASP y características)
```

## Instalación

Requiere Python 3.12 o superior y git.

```
python -m venv .venv
.venv\Scripts\activate          # en Linux o macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Reproducir las fases 1 a 3

```
python scripts/descargar_fuentes.py    # clona OWASP Benchmark Java y Python en data/raw
python scripts/construir_dataset.py    # fase Sample: genera data/dataset_vulnerabilidades.csv
python scripts/preprocesar.py          # fase Modify: genera data/processed y models/preprocesador.joblib
python scripts/auditar_sesgo.py        # comprueba que el dataset no tenga atajos que revelen la etiqueta
```

Los notebooks se ejecutan desde la carpeta `notebooks/` y leen los archivos generados por estos scripts. Para volver a ejecutarlos todos:

```
cd notebooks
python -m jupyter nbconvert --to notebook --execute --inplace 01_sample.ipynb 02_explore.ipynb 03_modify.ipynb
```

Todos los procesos aleatorios usan la semilla 42, así que el resultado es idéntico en cada ejecución.
