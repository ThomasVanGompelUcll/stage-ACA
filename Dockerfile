# ─── Stap 1: Frontend bouwen ─────────────────────────────────────────────────
# We gebruiken een aparte "build" container zodat de uiteindelijke image klein blijft.
FROM node:22-slim AS client-build

WORKDIR /app/scanner-app

# Kopieer alleen de package bestanden eerst (betere Docker cache)
COPY scanner-app/package.json ./package.json
COPY scanner-app/client/package.json ./client/package.json
COPY scanner-app/server/package.json ./server/package.json

# Installeer Node dependencies
RUN npm install --workspace client

# Kopieer de rest van de client source en bouw de React app
COPY scanner-app/client ./client
RUN npm run build --workspace client


# ─── Stap 2: Server bouwen ────────────────────────────────────────────────────
FROM node:22-slim AS server-build

WORKDIR /app/scanner-app

COPY scanner-app/package.json ./package.json
COPY scanner-app/client/package.json ./client/package.json
COPY scanner-app/server/package.json ./server/package.json

RUN npm install --workspace server

COPY scanner-app/server ./server
RUN npm run build --workspace server


# ─── Stap 3: Uiteindelijke image ──────────────────────────────────────────────
# Bevat zowel Node.js als Python
FROM node:22-slim

# Installeer Python en pip
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Kopieer de gebouwde server
COPY --from=server-build /app/scanner-app/node_modules ./scanner-app/node_modules
COPY --from=server-build /app/scanner-app/server/dist ./scanner-app/server/dist
COPY scanner-app/server/package.json ./scanner-app/server/package.json
COPY scanner-app/package.json ./scanner-app/package.json

# Kopieer de gebouwde React frontend
COPY --from=client-build /app/scanner-app/client/dist ./scanner-app/client/dist

# Kopieer de Python scripts
COPY requirements.txt ./requirements.txt
COPY complete.py scan_bridge.py ./
COPY port_scan.py ./
COPY discovery_pipeline ./discovery_pipeline
COPY domain ./domain
COPY dns ./dns
COPY whoIs ./whoIs

# Installeer Python packages (geen venv nodig in Docker)
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Maak de results map aan (wordt later gemount als Azure Files volume)
RUN mkdir -p /app/results

# Vertel de Node.js server dat hij 'python3' moet gebruiken (geen .venv in Docker)
ENV PYTHON_EXECUTABLE=python3

# De poort die App Service verwacht
ENV PORT=8080
EXPOSE 8080

# Start de Express server
CMD ["node", "scanner-app/server/dist/index.js"]
