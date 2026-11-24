"""
Fase 3 (Modify): pipeline reproducible de preprocesamiento.

Toma data/dataset_vulnerabilidades.csv y produce en data/processed/:

  dataset_limpio.csv        registros depurados con código normalizado y etiquetas
  X_{train,val,test}.npz    matrices de características (dispersas)
  Y_{train,val,test}.csv    etiquetas multietiqueta (20 categorías OWASP + vulnerable)
  X_train_bal.npz / Y_train_bal.csv   entrenamiento con sobremuestreo de estratos minoritarios
  nombres_caracteristicas.txt
  resumen_preprocesamiento.json

y en models/preprocesador.joblib el ColumnTransformer ajustado con train,
que es el que usará la herramienta CLI para transformar código nuevo.

Uso:
    python scripts/preprocesar.py
"""

import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import RandomOverSampler
from scipy import sparse

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from vulnminer.catalogo import ETIQUETAS  # noqa: E402
from vulnminer.features import construir_preprocesador, limpiar_codigo  # noqa: E402

ENTRADA = RAIZ / "data" / "dataset_vulnerabilidades.csv"
SALIDA = RAIZ / "data" / "processed"
MODELOS = RAIZ / "models"
SEMILLA = 42
COLUMNAS_Y = ETIQUETAS + ["vulnerable"]


def cargar():
    return pd.read_csv(ENTRADA, keep_default_na=False, dtype={"vulnerable": int})


def validar(df):
    """Descarta registros incompletos o con etiquetas incoherentes."""
    problemas = pd.Series("", index=df.index)
    problemas[df["codigo"].str.strip() == ""] = "codigo vacio"
    problemas[~df["vulnerable"].isin([0, 1])] = "etiqueta binaria invalida"
    problemas[(df["vulnerable"] == 1) & (df["owasp2025"] == "")] = "vulnerable sin categoria"
    problemas[(df["vulnerable"] == 0) & ((df["owasp2025"] != "") | (df["api2023"] != ""))] = \
        "seguro con categoria"
    invalidos = df[problemas != ""]
    return df[problemas == ""].copy(), invalidos.assign(motivo=problemas[problemas != ""])


def limpiar(df):
    df["codigo_limpio"] = [limpiar_codigo(c, t) for c, t in zip(df["codigo"], df["tipo_archivo"])]
    df["hash_limpio"] = df["codigo_limpio"].map(
        lambda s: hashlib.sha256(" ".join(s.split()).encode("utf-8")).hexdigest())
    return df


def deduplicar(df):
    """
    Tras normalizar, dos registros pueden quedar idénticos. Si sus etiquetas
    difieren se eliminan ambos (no hay forma de saber cuál es correcta); si
    coinciden se conserva uno, priorizando train > val > test para no dejar
    en evaluación código que el modelo ya vio.
    """
    orden = {"train": 0, "val": 1, "test": 2}
    df = df.assign(_orden=df["particion"].map(orden)).sort_values(["hash_limpio", "_orden"])
    etiquetas = df.groupby("hash_limpio")[["vulnerable", "owasp2025", "api2023"]].nunique()
    conflictivos = etiquetas[(etiquetas > 1).any(axis=1)].index
    n_conflicto = int(df["hash_limpio"].isin(conflictivos).sum())
    df = df[~df["hash_limpio"].isin(conflictivos)]
    antes = len(df)
    df = df.drop_duplicates("hash_limpio", keep="first").drop(columns="_orden")
    return df.sort_values("id").reset_index(drop=True), n_conflicto, antes - len(df)


def normalizar_etiquetas(df):
    """Une ambos estándares en una lista de etiquetas y la binariza."""
    def lista(fila):
        return [e for e in (fila["owasp2025"].split(";") + fila["api2023"].split(";")) if e]

    df["etiquetas"] = df.apply(lambda f: ";".join(lista(f)), axis=1)
    Y = pd.DataFrame(0, index=df.index, columns=COLUMNAS_Y)
    for i, etiquetas in df["etiquetas"].items():
        for e in filter(None, etiquetas.split(";")):
            Y.loc[i, e] = 1
    Y["vulnerable"] = df["vulnerable"]
    return df, Y


def balancear(X, Y, estrato, minimo):
    """
    Sobremuestreo aleatorio de los estratos (categoría, etiqueta) con menos de
    `minimo` ejemplos. Se duplican filas completas, así que las etiquetas
    multietiqueta de cada fila se conservan intactas.
    """
    conteo = estrato.value_counts()
    objetivo = {k: max(v, minimo) for k, v in conteo.items()}
    ros = RandomOverSampler(sampling_strategy=objetivo, random_state=SEMILLA)
    idx = np.arange(len(estrato)).reshape(-1, 1)
    idx_bal, _ = ros.fit_resample(idx, estrato.to_numpy())
    idx_bal = idx_bal.ravel()
    return X[idx_bal], Y.iloc[idx_bal].reset_index(drop=True)


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    MODELOS.mkdir(exist_ok=True)

    df = cargar()
    n_inicial = len(df)
    df, invalidos = validar(df)
    df = limpiar(df)
    df, n_conflicto, n_dup = deduplicar(df)
    df, Y = normalizar_etiquetas(df)

    particiones = {p: df.index[df["particion"] == p] for p in ("train", "val", "test")}
    preprocesador = construir_preprocesador()
    columnas = ["codigo_limpio", "tipo_archivo"]
    X = {"train": preprocesador.fit_transform(df.loc[particiones["train"], columnas])}
    for p in ("val", "test"):
        X[p] = preprocesador.transform(df.loc[particiones[p], columnas])

    for p, idx in particiones.items():
        sparse.save_npz(SALIDA / f"X_{p}.npz", sparse.csr_matrix(X[p]))
        Y.loc[idx].to_csv(SALIDA / f"Y_{p}.csv", index=False)

    train = df.loc[particiones["train"]]
    estrato = (train["categoria_vuln"] + "_" + train["vulnerable"].astype(str)).reset_index(drop=True)
    minimo = int(estrato.value_counts().median())
    X_bal, Y_bal = balancear(sparse.csr_matrix(X["train"]), Y.loc[particiones["train"]], estrato, minimo)
    sparse.save_npz(SALIDA / "X_train_bal.npz", X_bal)
    Y_bal.to_csv(SALIDA / "Y_train_bal.csv", index=False)

    nombres = preprocesador.get_feature_names_out()
    (SALIDA / "nombres_caracteristicas.txt").write_text("\n".join(nombres), encoding="utf-8")
    joblib.dump(preprocesador, MODELOS / "preprocesador.joblib")

    df.drop(columns=["codigo"]).to_csv(SALIDA / "dataset_limpio.csv", index=False, encoding="utf-8")

    bloques = {nombre: len(t.get_feature_names_out())
               for nombre, t, _ in preprocesador.transformers_ if nombre != "remainder"}
    resumen = {
        "registros_iniciales": n_inicial,
        "descartados_por_validacion": len(invalidos),
        "descartados_por_conflicto_de_etiqueta": n_conflicto,
        "duplicados_tras_normalizar": n_dup,
        "registros_finales": len(df),
        "por_particion": {p: len(i) for p, i in particiones.items()},
        "caracteristicas_por_bloque": bloques,
        "caracteristicas_totales": len(nombres),
        "minimo_por_estrato_tras_balanceo": minimo,
        "train_balanceado": int(X_bal.shape[0]),
    }
    (SALIDA / "resumen_preprocesamiento.json").write_text(
        json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(resumen, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
