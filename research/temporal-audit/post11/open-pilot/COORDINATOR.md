# Coordinación · Coordination

El generador produce dos ZIP de lectura, un manifiesto público del protocolo y una carpeta privada COORDINATION con la correspondencia de los tickets. Antes de repartir, acuerda participación voluntaria y privada, pseudónimos de sesión, uso de ayudas, fecha límite y canal de devolución. Anota exposición previa a los casos, abandonos y datos faltantes. No reveles la correspondencia al panel.

Recibe los A.sqlite y B.sqlite sellados en COORDINATION y conserva los recibos. El verificador comprueba los sellos y el contenido de las fichas. Contrasta la huella de cada recibo a través del canal previamente acordado. Desde la carpeta generada, ejecuta:

    python3 review.py report COORDINATION
    python3 review.py adjudicate COORDINATION

La tercera persona examina discrepancias, deja evidencia y anota sus segundos activos con el comando mostrado por `python3 review.py adjudicate --help`. Vuelve a ejecutar el informe después. Conserva las dos decisiones originales y los indeterminados. Cuando falte una devolución íntegra o existan abandonos, declara la cobertura y respeta el procedimiento del protocolo base. No sustituyas decisiones humanas por simulaciones. Acuerda el plazo de borrado local y comparte únicamente lo que autoricen los participantes.

Keep the ticket map private. Collect sealed packets separately and reconcile their receipt digests. The third reader adjudicates only after independent decisions are sealed. Preserve disagreement, missing data and unresolved cases. Report paired cases, simple agreement, κ, active person-minutes and adjudication separately. Minutes per case measure active reviewing time. They exclude wait times and preparation. The command-line examples above assume Python 3.10+ (Windows: use `py -3`).
