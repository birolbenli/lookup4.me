# lookup4.me

Simple DNS, email authentication and SSL lookup tools.

## Tools

- MX Lookup
- SPF Lookup
- DKIM Lookup (common selector detection + host/IP chain resolution)
- DMARC Lookup
- SSL Checker (up to 10 domains at once)
- Reverse DNS Lookup
- SMTP Test (port 25)

## Quick start (Docker)

```bash
docker compose up --build -d
```

Open [http://localhost:8080](http://localhost:8080).

Optional Buy Me a Coffee URL:

```bash
export BUYMEACOFFEE_URL=https://www.buymeacoffee.com/yourpage
docker compose up --build -d
```

## Local development

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## VPS deploy

On the server:

```bash
git clone https://github.com/birolbenli/lookup4.me.git
cd lookup4.me
docker compose up --build -d
```

Map/proxy port `8080` as needed (nginx, Caddy, etc.).

## License

MIT
