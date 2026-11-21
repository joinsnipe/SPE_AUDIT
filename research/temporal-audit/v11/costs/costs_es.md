## Coste de una decisión equivocada

Una falsa alerta, una afirmación posterior mal liberada y un turno humano representan costes distintos. Definimos la pérdida como la suma de cuatro cuentas multiplicadas por sus pesos. FP es un control determinado que se marca positivo. FN es un positivo que se cierra como «otro». R cuenta todas las derivaciones, incluso las que luego se resuelvan bien. U es una referencia indeterminada que el sistema cerró en cualquier sentido. Por tanto, un positivo remitido a revisión reduce la sensibilidad automática, pero en esta matriz se carga una vez como revisión. No se presupone que el revisor corrija siempre ni se conocen sus costes posteriores.

| Escenario ilustrativo | Falsa alerta (FP) | Positivo liberado (FN) | Revisión (R) | Ambigüedad cerrada (U) | Capacidad supuesta |
|---|---:|---:|---:|---:|---|
| Revisión administrativa | 12 | 25 | 1 | 14 | Sin límite prefijado de derivación |
| Servicio de atención | 4 | 5 | 2 | 3 | Como máximo 20 % de casos derivados |

Las cifras son unidades convencionales para análisis de sensibilidad. No son estimaciones económicas ni umbrales jurídicos. El coste de ambos aciertos se fija en cero. Los escenarios se definieron después de observar el resultado principal. Para cada escenario, el algoritmo de selección solo recibe los 48 casos de calibración y compara umbrales de 2 a 8 y la alternativa de revisar todo. Un umbral más alto exige más evidencia para cerrar automáticamente una proposición. En empates se prefiere el umbral numérico más alto.

En calibración, ambos escenarios eligieron 5, con 6/48 derivaciones y cero errores entre las decisiones. En el desafío nuevo, ese mismo umbral produjo una falsa alerta, cero positivos liberados como «otro», 24 revisiones y tres ambigüedades cerradas. En el escenario administrativo son **78 unidades**, frente a **48** al revisar los 48 casos. En atención son **61 unidades** y se deriva el 50 %, superando el presupuesto del 20 %. Ningún umbral numérico probado cumplió ese presupuesto en los 48 casos nuevos. La tabla completa por umbral está en [scenarios.json](costs/scenarios.json).

La decisión operativa depende del coste local de una intervención, de la prevalencia y de lo que le ocurra a quien reciba la alerta. Con estos datos aplazaríamos el cierre autónomo de expedientes administrativos. Los tiempos que recojan los revisores permitirán sustituir los pesos ilustrativos por costes medidos y repetir la selección en una muestra representativa.
