#!/bin/bash
# Setup Neo4j Aura — aplica constraints/índices en la instancia remota.
# Requiere NEO4J_URI y NEO4J_PASSWORD como variables de entorno o .env.
set -e

if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

if [ -z "$NEO4J_URI" ] || [ -z "$NEO4J_PASSWORD" ]; then
  echo "ERROR: NEO4J_URI y NEO4J_PASSWORD son obligatorios."
  echo ""
  echo "Pasos para obtenerlos:"
  echo "  1. Ir a https://console.neo4j.io"
  echo "  2. Crear instancia AuraDB Free (o Professional)"
  echo "  3. Copiar URI y password al generar las credenciales"
  echo "  4. Añadir a Secret Manager:"
  echo "     gcloud secrets create NEO4J_URI --data-file=- <<< 'bolt+ssc://...'"
  echo "     gcloud secrets create NEO4J_PASSWORD --data-file=- <<< 'tu_password'"
  exit 1
fi

echo ">>> Aplicando constraints en Neo4j Aura: $NEO4J_URI"
python3 -c "
from core.graph_client import GraphClient
GraphClient.apply_constraints()
print('Constraints aplicados correctamente.')
"
echo ">>> Neo4j Aura setup completo."
