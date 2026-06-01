# quantum-shield-go — Контекст проекту для Claude

## Що це за проект

Post-quantum cryptography API сервер на Go.
Власник: Andrevozni. Проект написаний повністю в Claude Code сесіях.

## Технічний стек

- **Go 1.25.0** — знаходиться в `C:\Users\USER\go125\bin\go.exe`
  - `go-sdk` = Go 1.24.3 (НЕ використовувати для тестів — не підтримує go-slh-dsa)
  - Правильна команда: `& "C:\Users\USER\go125\bin\go.exe" test ...`
- **GOPROXY**: `https://proxy.golang.org,direct`
- **Module**: `github.com/quantum-shield/quantum-shield-go`

## Запуск тестів

```powershell
cd C:\Users\USER\quantum_shield_go
$env:GOPROXY = "https://proxy.golang.org,direct"
& "C:\Users\USER\go125\bin\go.exe" test -race ./... -timeout 180s
```

## Алгоритми (NIST FIPS 203/204/205)

- **ML-KEM-768 / ML-KEM-1024** — `crypto/mlkem` (Go stdlib)
- **ML-DSA-65 / ML-DSA-87** — `github.com/cloudflare/circl`
- **SLH-DSA** — `github.com/trailofbits/go-slh-dsa`
- **AES-256-GCM** — hybrid encryption (KEM + AEAD)
- **SHA3-256, SHAKE128/256** — Keccak

## Структура проекту

```
cmd/server/          — HTTP API сервер
pkg/api/server.go    — всі HTTP handlers (~2700 рядків)
pkg/middleware/      — RequireJSON, RateLimit, Auth
internal/kem/        — ML-KEM обгортка
internal/dsa/        — ML-DSA обгортка
internal/slhdsa/     — SLH-DSA обгортка
internal/hybrid/     — KEM + AES-GCM
internal/channel/    — encrypted channels (forward secrecy)
internal/vault/      — Shamir Secret Sharing на GF(256)
internal/ca/         — Certificate Authority
internal/cluster/    — Raft consensus (hashicorp/raft)
internal/audit/      — hash-chain audit log
internal/fips/       — FIPS compliance probes
test/redteam/        — 8 рівнів red team тестів
test/security/       — pentest тести
test/integration/    — інтеграційні тести
```

## Red Team тести — статус

Всього: **148 тестів безпеки** (94 red team + 54 pentest/integration)
Результат: **25/25 пакетів PASS, 0 data races**

| Рівень | Файл | Кількість | Статус |
|--------|------|-----------|--------|
| L1 | redteam1_test.go | 12 атак | ✅ |
| L2 | redteam2_test.go | 12 атак | ✅ |
| L3 | redteam3_test.go | 14 атак | ✅ |
| L4 | redteam4_test.go | 15 атак | ✅ |
| L5 | redteam5_test.go | 11 атак | ✅ (2 баги знайдено і виправлено) |
| L6 | redteam6_test.go | 11 атак | ✅ |
| L7 | redteam7_test.go | 6 атак  | ✅ |
| L8 | redteam8_test.go | 13 атак | ✅ (1 баг знайдено і виправлено) |

## Реальні вразливості знайдені і виправлені

### Баг 1 — Bootstrap Secret Timing Oracle (L5)
**Файл:** `pkg/api/server.go` — `handleBootstrap`
**Проблема:** `bootstrapSecret == providedSecret` — змінно-часове порівняння рядків
**Виправлення:** `subtle.ConstantTimeCompare([]byte(s.bootstrapSecret), []byte(provided)) == 1`

### Баг 2 — Channel Handshake TOCTOU Race (L5)
**Файл:** `pkg/api/server.go` — `handleChannelComplete`
**Проблема:** check-then-act між перевіркою сесії і її видаленням без блокування
**Виправлення:** atomic claim під write lock перед декриптуванням KEM

### Баг 3 — Empty Content-Type Bypass (L8)
**Файл:** `pkg/middleware/middleware.go` — `RequireJSON`
**Проблема:** `if ct != "" && !strings.HasPrefix(...)` — порожній CT проходив
**Виправлення:** `if ct == "" || !strings.HasPrefix(ct, "application/json")`

## Важливі технічні факти

### ML-KEM публічний ключ
- Розмір: 1184 байти (ML-KEM-768)
- Структура: перші 1152 байти = t_hat (3×256 коефіцієнти по 12 біт), останні 32 байти = ρ seed
- Коефіцієнти завжди в [0, 3328] — якщо ≥ 3329, NTT reduction зламана
- Bit 11 кожного коефіцієнта має ймовірність ≈ 38.5% (бо q=3329 < 4096) — це НОРМА, не баг
- Shannon entropy публічного ключа ≈ 7.957 bits/byte (не 8.0 через q=3329 < 2^12)

### KyberSlash (IACR TCHES 2025)
Go's `crypto/mlkem` використовує Barrett reduction замість `DIV` → NOT VULNERABLE

### FO-Transform timing (IACR 2024/060)
Тест показав distance=0.20 (< 10) → constant-time ✅

### Keccak/SHAKE
- SHAKE128 rate = 136 bytes
- JSON API приймає тільки valid UTF-8 plaintext (0xFF байти як JSON string = replacement chars)

## API Endpoints

```
POST /auth/token          — отримати JWT токен
POST /keys/generate       — згенерувати ML-KEM ключову пару
GET  /keys                — список ключів
POST /encrypt             — ML-KEM + AES-256-GCM шифрування
POST /decrypt             — дешифрування
POST /sign                — ML-DSA підпис
POST /verify-signature    — верифікація підпису
POST /ca/init             — ініціалізація CA
POST /ca/sign             — видати сертифікат
POST /ca/verify           — верифікувати сертифікат
POST /vault/split         — Shamir SSS розбивка
POST /vault/reconstruct   — Shamir SSS відновлення
POST /channel/init        — ініціалізація зашифрованого каналу
POST /channel/complete    — завершення KEM handshake
POST /channel/seal        — зашифрувати повідомлення в каналі
POST /channel/open        — розшифрувати повідомлення з каналу
POST /kdf/hkdf            — HKDF деривація ключа
POST /kdf/argon2          — Argon2id деривація
POST /threshold/init      — threshold signature ініціалізація
POST /threshold/sign      — threshold signing round
POST /audit/log           — аудит записи
GET  /audit/verify        — верифікація audit chain
GET  /health/fips         — FIPS compliance probe ({"overall":"pass"|"fail"})
GET  /health/ready        — liveness/readiness
```

## Допоміжні функції в тестах (test/redteam/helpers_test.go)

```go
srv(t, opts...)              — запустити тестовий сервер
token(t, ts, userID, roles)  — отримати JWT токен
genKey(t, ts, tok, level)    — згенерувати ключ, повернути (keyID, pubKey)
jreq(t, ts, method, path, body, tok) — HTTP запит, повернути (statusCode, responseMap)
copyMap(m)                   — shallow copy map[string]any
```

## Що залишилось зробити (якщо продовжувати)

- [ ] GitHub публікація (власник хоче відкритий код для community feedback + bug reports)
- [ ] README.md з описом проекту
- [ ] THREAT_MODEL.md
- [ ] GitHub Security Advisories налаштувати
- [ ] Можливо: незалежний аудит (Trail of Bits) якщо буде комерційне використання

## Контекст власника

- Хоче публікувати на GitHub для community (не для слави, а щоб люди знаходили баги)
- Турбується що відкритий код "вкрадуть" — пояснено що git history захищає авторство
- Хоче використовувати як портфоліо для роботи
- Проект будувався протягом декількох сесій Claude Code
