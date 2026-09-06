# backend

[![License: Klovy](https://img.shields.io/badge/License-Klovy-blue.svg)](LICENSE)

The official backend of Klovy Chat.

Oficjalny serwer API i WebSocket komunikatora **Klovy Chat**. Napisany w Rust (Axum + Actix-web), z MongoDB Atlas, Cloudflare R2 i skanowaniem załączników ClamAV.

Produkcja: [api.klovy.chat](https://api.klovy.chat)

---

## O projekcie

Backend obsługuje aplikację Klovy Chat: konta, kanały, wiadomości, znajomych, zaproszenia, przesyłanie plików, połączenia głosowe (LiveKit) oraz obecność na żywo przez WebSocket.

Publiczny ruch wchodzi na Axum (CORS, proxy, limity). Wewnętrzne API i upgrade WebSocket obsługuje Actix-web. Załączniki lądują w Cloudflare R2 (osobny bucket kwarantanny), a ClamAV skanuje je zanim trafią na CDN.

### Ekosystem

| Repo | Rola |
|------|------|
| [backend](https://github.com/klovy-chat/backend) | API i WebSocket |
| [frontend](https://github.com/klovy-chat/frontend) | Aplikacja web (`app.klovy.chat`) |
| [website](https://github.com/klovy-chat/website) | Strona (`klovy.chat`) |
| [application](https://github.com/klovy-chat/application) | Desktop (Tauri) |

---

## Funkcje

- Autoryzacja JWT, sesje, odświeżanie tokenów, 2FA (TOTP)
- Kanały, wiadomości, załączniki, pinowanie, wyszukiwanie
- Znajomi, kontakty, zaproszenia
- WebSocket: obecność, typing, szyfrowane ramki
- Głos (LiveKit)
- Upload na Cloudflare R2 + skan ClamAV
- Limity rejestracji, Cloudflare Turnstile
- GIF-y i stickery (Giphy)

---

## Wymagania

- **Rust** (stable, [rustup](https://rustup.rs))
- **MongoDB Atlas** (connection string w `MONGODB_URI`)
- **Docker** i Docker Compose — opcjonalnie (kontener + ClamAV)
- **ClamAV** — wymagany na produkcji; lokalnie: `docker compose --profile scan`

---

## Uruchomienie lokalne

```bash
git clone https://github.com/klovy-chat/backend.git
cd backend
cp .env.example .env
```

W `.env` wstaw swój connection string **MongoDB Atlas** (`MONGODB_URI`). Potem:

```bash
cargo run
```

Szablon [`.env.example`](.env.example) ma gotowe wartości na `127.0.0.1` (port `8080`, klucze dev). Turnstile i ClamAV w `development` nie są wymagane. Upload załączników potrzebuje prawdziwego Cloudflare R2 — dummy `R2_*` wystarcza, żeby proces wstał.

Opcjonalny skaner:

```bash
docker compose --profile scan up -d
```

W `.env` ustaw wtedy `CLAMAV_HOST=127.0.0.1:3310`.

Przykładowy reverse proxy: [Caddyfile.example](Caddyfile.example) (`cp Caddyfile.example Caddyfile`). Podmień `app.example.com` i `ChatApp` na swoje wartości. Caddy na `:8081` → backend na `:8080`.

Build produkcyjny:

```bash
cargo build --release
./target/release/klovy-chat-server
```

---

## Docker

Skaner (opcjonalnie):

```bash
docker compose --profile scan up -d
```

Pełny stack produkcyjny (obraz backendu + ClamAV):

```bash
docker compose --profile scan up -d --build
```

Produkcja w oficjalnym repo jest wdrażana przez GitHub Actions (`.github/workflows/deploy.yml`) przy pushu na `main`. Forki tego nie robią.

---

## Zmienne środowiska

Szablon: [`.env.example`](.env.example) (`cp .env.example .env`). Nie commituj prawdziwego `.env`.

| Grupa | Zmienne |
|--------|---------|
| Serwer | `NODE_ENV`, `PORT`, `INTERNAL_HTTP_PORT`, `TRUST_PROXY` |
| Baza | `MONGODB_URI` (Atlas), `DB_NAME` |
| Auth | `JWT_KEY`, `FIELD_ENCRYPTION_KEY`, `TOKEN_HASH_KEY` |
| CORS / URL | `ORIGIN`, `FRONTEND_URL` |
| Proxy | `INTERNAL_PROXY_SECRET` |
| Captcha | `TURNSTILE_SECRET_KEY` |
| Storage | `R2_*`, `CDN_PUBLIC_BASE_URL`, `R2_QUARANTINE_BUCKET` |
| Skan | `CLAMAV_HOST` |
| Głos | `LIVEKIT_URL`, `LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET` |

Na produkcji wymagane są m.in. HTTPS w `ORIGIN` i `FRONTEND_URL`, osobny bucket kwarantanny R2 oraz ClamAV.

---

## Technologie

- **Rust** — serwer (`klovy-chat-server`)
- **Axum** — publiczny edge (CORS, proxy, limity)
- **Actix-web** — API REST i WebSocket
- **MongoDB Atlas** — dane (użytkownicy, kanały, wiadomości, sesje)
- **Cloudflare R2** — załączniki i CDN
- **ClamAV** — skan złośliwego oprogramowania
- **LiveKit** — połączenia głosowe
- **Argon2 / JWT / AES-GCM / TOTP** — hasła, tokeny, szyfrowanie pól, 2FA
- **Docker** — obraz i Compose

---

## Struktura projektu

```
backend/
├── src/
│   ├── main.rs              # Start: dotenv, Mongo, R2, indeksy, bind
│   ├── lib.rs               # Crate klovy_chat_server
│   ├── bin/                 # Narzędzia (encrypt-old-messages)
│   ├── controllers/         # Logika endpointów
│   ├── routes/              # /api/* (auth, channels, messages, …)
│   ├── model/               # Dokumenty Mongo
│   ├── ws/                  # WebSocket
│   ├── middlewares/         # Auth, CSRF, captcha, origin, IP
│   ├── loaders/             # Składanie serwerów Axum + Actix
│   └── utils/               # Auth, storage, scan, crypto, security
├── .github/workflows/       # Deploy produkcyjny
├── docker-compose.yml
├── Dockerfile
├── Caddyfile.example        # Przykładowy reverse proxy
├── Cargo.toml
└── .env.example             # Szablon środowiska (lokalny start)
```

Binarka: `klovy-chat-server`. Narzędzie migracji: `encrypt-old-messages`.

---

## Contributing

Kod jest publiczny na [Klovy License](LICENSE). Issue i pull requesty są mile widziane.

1. Zrób [fork](https://github.com/klovy-chat/backend/fork)
2. Utwórz branch: `git checkout -b feature/opis-zmiany`
3. Commit (bez `.env` i sekretów)
4. Otwórz pull request do `main`

Opisz w PR **co** i **dlaczego**. Drobne poprawki (docs, typo) też są OK.

---

## Bezpieczeństwo

Luki zgłaszaj prywatnie przez [GitHub Security Advisories](https://github.com/klovy-chat/backend/security/advisories/new). Nie otwieraj publicznego issue z exploitami.

---

## Licencja

Kod jest udostępniony na **[Klovy License](LICENSE)** — użycie osobiste, edukacyjne i niekomercyjne. Dystrybucja komercyjna, konkurencyjny komunikator oraz użycie marek Klovy wymagają pisemnej zgody Jakuba Maksymowicza. Zgłoszenie PR, błędu lub audytu bezpieczeństwa oznacza zgodę na warunki kontrybucji z licencji (pkt 7–11).

© 2026 [Jakub Maksymowicz](https://github.com/Klovy06)
