# tools.birolbenli.com

Simple DNS, email authentication and SSL lookup tools.

## Tools

- MX / SPF / DKIM / DMARC
- DNS / NS / CAA / WHOIS
- SSL Checker (up to 10 domains)
- HTTP Headers, Port Check
- Reverse DNS, Blacklist (DNSBL)
- SMTP Test (port 25)
- IP Lookup (`/ip`, curl-friendly)
- Email Header Analyzer (educational report)
- Mail Tester (random address + deliverability score)

### Mail Tester DNS

Set an MX record for your `MAILTEST_DOMAIN` (default `tools.birolbenli.com`) to this VPS IP, and expose port **25**.

### Admin panel

Open `/admin`, sign in with `ADMIN_USER` / `ADMIN_PASSWORD`, then link Google Authenticator (QR). Later logins ask for password + OTP. Whitelist IPs skip rate limits; blacklist IPs redirect to Google.

### Direct URLs

```text
/tools/smtp/mx1.example.com
/tools/mx/gmail.com
/tools/ssl/google.com,github.com
/tools/port/1.1.1.1:443
/tools/dns/example.com?type=TXT
```

```bash
curl http://HOST:8080/ip
curl http://HOST:8080/ip.json
```

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
