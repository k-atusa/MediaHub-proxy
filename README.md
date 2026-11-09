# MediaHub Proxy

MediaHub의 프록시 기반 스트리밍 및 파일 공유 버전입니다.

## 특징
- **임베딩 기반 선택적 가로채기(Embedded Selective Interception)**: `//go:embed all:public`을 통해 프록시 서버 자체의 `public` 디렉토리(및 로컬 `./public`)를 임베딩하며, 요청된 경로가 자체 `public` 내에 존재하는 파일(예: `core/adapter.js`, `core/drive.js` 등)일 경우 가로채서 서빙하고, 자체 `public`에 없는 파일(예: `index.html`, `js/app.js`, `css/...`, 스토리지 API 등)은 대상 오리진 서버(`target`)로 자동 중계합니다.
- **서버 측 평문 미디어 스트리밍**: 브라우저의 Service Worker 대신 프록시 서버가 직접 1MB 청크 복호화 및 HTTP 206 Partial Content Range 스트리밍을 제공합니다.
- **스트리밍 세션 관리**: 수명 최대 1일(24시간)이며, 클라이언트의 재생 종료 시 즉시 파기(`DELETE /api/stream/{id}`)됩니다.
- **키 없는 공유 세션 관리**: 파일 키 없이 공유 가능한 공유 링크를 생성하며, 서버가 기본 7일의 수명을 관리합니다.
- **메모리 내 마스킹 보안**: 파일 키, 폴더 ID, 파일 PID 등 중요 정보는 디스크에 저장하지 않고 **메모리에서만 5-Round Feistel Network 기반 마스커(Masker)로 XOR 마스킹**하여 보관합니다.
- **1MB 이하 데이터 인메모리 캐시**: 1MB 이하 데이터(복호화된 청크, 정적 파일)에 대해 TTL 3시간 및 용량 제한(기본 32MB)을 가진 LRU 캐시를 운영합니다.

## 디렉토리 구조
```
MediaHub-proxy/
├── code/
│   ├── server.go          # 프록시 서버 메인, 리버스 프록시, 라우팅 및 가로채기
│   ├── streaming.go       # 스트리밍 세션 및 평문 Range 스트리밍 엔진
│   ├── utils.go           # 마스커(Masker), 인메모리 캐시(TTL 3h), 공유 세션(TTL 7d)
│   ├── server_test.go     # 단위 테스트
│   ├── go.mod             # Go 모듈 파일
│   └── public/
│       └── core/
│           ├── adapter.js # 프록시 통신 및 공유/스트리밍 세션 프론트 어댑터
│           └── drive.js   # 프록시 환경 상태 관리
└── _example/              # 바닐라 웹 서버 및 USAG 라이브러리 예제
```

## 설정 (`config/config.json`)
서버 실행 시 자동으로 기본 설정 파일이 생성됩니다.
```json
{
  "target": "https://localhost:8443",
  "security": "selftls",
  "port": "8444",
  "http": false,
  "loopback": false,
  "cert": "./certs/cert.pem",
  "key": "./certs/key.pem",
  "cache_mb": 32,
  "max_sessions": 5000
}
```
- **`target`**: 바닐라 웹 서버 대상 URL (예: `"https://localhost:8443"` 또는 `"http://localhost:8443"`).
- **`security`**: 바닐라 서버와의 연결 보안 수준 (`"tls"` | `"selftls"` | `"plain"`).
  - `"tls"` (기본값): HTTPS 연결 및 공인 CA 인증서 유효성을 엄격히 검증합니다.
  - `"selftls"`: HTTPS 연결을 사용하되, 사설/자체 서명(Self-signed) 인증서를 수용합니다 (`InsecureSkipVerify: true`).
  - `"plain"`: TLS 암호화 없이 일반 평문 HTTP로 통신합니다.

## 빌드 및 실행
```bash
cd code
go build -ldflags="-s -w" -trimpath -o server.exe .
./server.exe
```

