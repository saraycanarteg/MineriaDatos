"""
Auditoría de sesgo del dataset preprocesado.

Busca señales que permitan adivinar si un fragmento es vulnerable sin entender
la vulnerabilidad: metadatos (fuente, tipo de archivo, longitud), nombres
usados en las plantillas, literales de relleno de Benchmark y, finalmente, qué
características usa un clasificador lineal sencillo. Este clasificador es solo
una sonda de diagnóstico, no el modelo de la fase Model, y se evalúa con
validación cruzada dentro de train para no consumir validación ni prueba.

Uso:
    python scripts/auditar_sesgo.py
"""

import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse
from scipy.stats import chi2_contingency
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, cross_val_score

RAIZ = Path(__file__).resolve().parents[1]
PROCESADOS = RAIZ / "data" / "processed"

ENTIDADES = r"(Order|Invoice|Account|Ticket|Payment|Profile|Product|Shipment|Booking|Document)"
LITERAL = re.compile(r'"([^"\n]{2,60})"|\'([^\'\n]{2,60})\'')


def cargar():
    df = pd.read_csv(PROCESADOS / "dataset_limpio.csv", keep_default_na=False)
    train = df[df.particion == "train"].reset_index(drop=True)
    X = sparse.load_npz(PROCESADOS / "X_train.npz")
    nombres = (PROCESADOS / "nombres_caracteristicas.txt").read_text(encoding="utf-8").splitlines()
    return df, train, X, nombres


def sonda_metadatos(train):
    """Exactitud al predecir la etiqueta solo con fuente, tipo de archivo y longitud."""
    M = pd.get_dummies(train[["proyecto_origen", "tipo_archivo"]]).astype(float)
    M["log_longitud"] = np.log1p(train.codigo_limpio.str.len())
    cv = GroupKFold(n_splits=5)
    acc = cross_val_score(LogisticRegression(max_iter=2000), M, train.vulnerable,
                          groups=train.grupo, cv=cv, scoring="accuracy")
    return acc.mean()


def balance_entidades(df):
    """Prueba chi-cuadrado de independencia entre la entidad de la plantilla y la etiqueta."""
    c = df[df.proyecto_origen == "casos_controlados"]
    ent = c.codigo_limpio.str.extract(ENTIDADES)[0]
    tabla = pd.crosstab(ent, c.vulnerable)
    return tabla, chi2_contingency(tabla).pvalue


def longitud_por_clase(df):
    lineas = df.codigo_limpio.str.count("\n")
    return lineas.groupby([df.proyecto_origen, df.vulnerable]).median().unstack()


def literales_sesgados(df, minimo=15, umbral=0.3):
    """Literales de Benchmark cuya presencia se asocia fuertemente con una clase."""
    b = df[df.proyecto_origen != "casos_controlados"]
    conteo = {}
    for codigo, v in zip(b.codigo_limpio, b.vulnerable):
        for lit in {a or c for a, c in LITERAL.findall(codigo)}:
            conteo.setdefault(lit, [0, 0])[v] += 1
    filas = [(lit, n0, n1, n1 / (n0 + n1)) for lit, (n0, n1) in conteo.items() if n0 + n1 >= minimo]
    t = pd.DataFrame(filas, columns=["literal", "seguros", "vulnerables", "prop_vulnerable"])
    return t[(t.prop_vulnerable - 0.5).abs() > umbral].sort_values("prop_vulnerable")


def sonda_lineal(train, X, nombres, n=15):
    """Exactitud con validación cruzada y características con mayor peso de una regresión logística."""
    cv = GroupKFold(n_splits=5)
    modelo = LogisticRegression(max_iter=3000)
    acc = cross_val_score(modelo, X, train.vulnerable, groups=train.grupo, cv=cv, scoring="accuracy")
    modelo.fit(X, train.vulnerable)
    coef = modelo.coef_[0]
    orden = np.argsort(coef)
    limpiar = lambda i: nombres[i].replace("tfidf__", "").replace("ind__", "[ind] ")
    pesos = pd.DataFrame({
        "hacia_seguro": [limpiar(i) for i in orden[:n]],
        "hacia_vulnerable": [limpiar(i) for i in orden[::-1][:n]],
    })
    return acc.mean(), pesos


def main():
    df, train, X, nombres = cargar()
    pd.set_option("display.width", 160)

    print(f"1. Sonda de metadatos (fuente, tipo, longitud): exactitud {sonda_metadatos(train):.3f} "
          f"(0.5 = sin señal)")
    tabla, p = balance_entidades(df)
    print(f"\n2. Entidad de plantilla vs etiqueta: p-valor chi-cuadrado {p:.3f}")
    print(tabla.T.to_string())
    print("\n3. Mediana de líneas por fuente y clase")
    print(longitud_por_clase(df).to_string())
    print("\n4. Literales de Benchmark asociados a una clase")
    print(literales_sesgados(df).to_string(index=False))
    acc, pesos = sonda_lineal(train, X, nombres)
    print(f"\n5. Sonda lineal sobre todas las características: exactitud CV {acc:.3f}")
    print(pesos.to_string(index=False))


if __name__ == "__main__":
    main()
